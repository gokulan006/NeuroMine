from flask import Flask, request, jsonify, render_template, redirect, send_file, url_for, session, flash
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
import re
 
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.chains import create_retrieval_chain, create_history_aware_retriever
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_community.vectorstores import FAISS
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.output_parsers import StrOutputParser

from src.prompt import SYSTEM_PROMPT, CONTEXTUALIZE_Q_N_SYSTEM_PROMPT
from src.helper import get_session_history, create_embedding_fnc

from flask_dance.contrib.google import make_google_blueprint, google

import pandas as pd
from datetime import datetime

# Load env vars
load_dotenv()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

groq_api = os.getenv("GROQ_API_KEY")
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'


# Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Google OAuth setup
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_to="chat"
)

app.register_blueprint(google_bp, url_prefix="/login")

users = {}
chat_store = {}

# Initialize components
model = ChatGroq(model='llama-3.3-70b-versatile', api_key=groq_api)
embeddings = create_embedding_fnc()

# Load the FAISS index
faiss_db = FAISS.load_local(
    "faiss_index",
    embeddings,
    allow_dangerous_deserialization=True   
)

retriever = faiss_db.as_retriever()

contextualize_q_prompt = ChatPromptTemplate.from_messages([
    ('system', CONTEXTUALIZE_Q_N_SYSTEM_PROMPT),
    MessagesPlaceholder("chat_history"),
    ('human', '{input}')
])

qa_prompt = ChatPromptTemplate.from_messages([
    ('system', SYSTEM_PROMPT),
    MessagesPlaceholder("chat_history"),
    ('human', '{input}')
])

output_parser = StrOutputParser()
history_aware_retriever = create_history_aware_retriever(model, retriever, contextualize_q_prompt)
qa_chain = create_stuff_documents_chain(model, qa_prompt)
qa_chain = qa_chain | output_parser
retrieval_chain = create_retrieval_chain(history_aware_retriever, qa_chain)

rag_chain = RunnableWithMessageHistory(
    retrieval_chain,
    lambda session_id: get_session_history(session_id, chat_store),
    input_messages_key="input",
    history_messages_key="chat_history",
    output_messages_key="answer"
)

# News CSV Path
NEWS_CSV_PATH = 'news_articles.csv'

def load_news_articles():
    try:
        df = pd.read_csv(NEWS_CSV_PATH)
        articles = df.to_dict('records')
        for article in articles:
            article['published_date'] = datetime.strptime(article['published_date'], '%Y-%m-%d').date()
        articles.sort(key=lambda x: x['published_date'], reverse=True)
        return articles
    except Exception as e:
        print(f"Error loading news articles: {e}")
        return []

def validate_password_strength(password):
    """
    Validate password strength and return score and feedback
    """
    if not password:
        return {'score': 0, 'level': 'none', 'feedback': []}
    
    feedback = []
    score = 0
    
    # Length check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
     
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    
     
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    
     
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Add numbers")
    
     
    if re.search(r'[^A-Za-z0-9]', password):
        score += 1
    else:
        feedback.append("Add special characters")
    
     
    if score < 3:
        level = 'weak'
    elif score < 4:
        level = 'medium'
    else:
        level = 'strong'
    
    return {
        'score': score,
        'level': level,
        'feedback': feedback,
        'is_valid': score >= 3  # Minimum acceptable strength
    }

def validate_username(username):
    """
    Validate username format and availability
    """
    if not username:
        return {'valid': False, 'message': 'Username is required'}
    
    if len(username) < 3:
        return {'valid': False, 'message': 'Username must be at least 3 characters long'}
    
    if len(username) > 20:
        return {'valid': False, 'message': 'Username must be less than 20 characters'}
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return {'valid': False, 'message': 'Username can only contain letters, numbers, and underscores'}
    
    if username in users:
        return {'valid': False, 'message': 'Username already exists'}
    
    return {'valid': True, 'message': 'Username is available'}

def validate_email(email):
    """
    Validate email format
    """
    email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_pattern, email):
        return {'valid': False, 'message': 'Invalid email format'}
    
    return {'valid': True, 'message': 'Valid email'}

# Routes
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        terms_accepted = request.form.get('terms') == 'on'
        
        # Validation
        errors = []
        
        # Username validation
        username_validation = validate_username(username)
        if not username_validation['valid']:
            errors.append(username_validation['message'])
        
        # Email validation
        email_validation = validate_email(email)
        if not email_validation['valid']:
            errors.append(email_validation['message'])
        
        # Password validation
        password_validation = validate_password_strength(password)
        if not password_validation['is_valid']:
            errors.append(f"Password is too weak. {', '.join(password_validation['feedback'])}")
        
        # Password confirmation
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        # Terms acceptance
        if not terms_accepted:
            errors.append("You must accept the Terms of Service and Privacy Policy")
        
        # If there are errors, flash them and redirect back
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('signup.html')
        
        # Check if email is already registered (optional)
        for existing_user, user_data in users.items():
            if isinstance(user_data, dict) and user_data.get('email') == email:
                flash('Email already registered', 'error')
                return render_template('signup.html')
        
        # Store user with additional information
        users[username] = {
            'password_hash': generate_password_hash(password),
            'email': email,
            'created_at': datetime.now()
        }
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Manual login
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = users.get(username)
        if user_data:
            # Handle both old (string) and new (dict) user data formats
            if isinstance(user_data, str):
                # Old format - just password hash
                password_hash = user_data
            else:
                # New format - dict with password_hash
                password_hash = user_data['password_hash']
            
            if check_password_hash(password_hash, password):
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('chat'))
        
        flash('Invalid username or password', 'error')
        return render_template('login.html')

    # If logged in with Google
    if google.authorized:
        resp = google.get("/oauth2/v2/userinfo")
        if resp.ok:
            user_info = resp.json()
            session['username'] = user_info["email"]
            flash('Logged in with Google!', 'success')
            return redirect(url_for('chat'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)

    # Revoke Google token if logged in with Google
    if google.authorized:
        token = google_bp.token["access_token"]
        requests.post(
            "https://accounts.google.com/o/oauth2/revoke",
            params={'token': token},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )
        del google_bp.token

    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("index.html", username=session['username'])

@app.route("/ask", methods=["POST"])
def ask():
    data = request.get_json()
    user_input = data.get("message")
    session_id = data.get("session_id")
    language = data.get("language", "en")
    
    if language == "hi":
        user_input = f"Answer this question in Hindi: {user_input}"
    
    try:
        result = rag_chain.invoke(
            {"input": user_input},
            config={"configurable": {"session_id": session_id}}
        )
        return jsonify({
            "answer": result['answer'] 
        })
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

@app.route("/news")
def news_page():
     
    return render_template("news.html", username=session['username'])

@app.route("/api/news")
def api_news():
    articles = load_news_articles()
    # articles = df.to_dict(orient="records")
    return jsonify(articles)

# API endpoints for client-side validation
@app.route('/api/validate-username', methods=['POST'])
def api_validate_username():
    """API endpoint for real-time username validation"""
    data = request.get_json()
    username = data.get('username', '').strip()
    
    validation = validate_username(username)
    return jsonify(validation)

@app.route('/api/validate-password', methods=['POST'])
def api_validate_password():
    """API endpoint for real-time password strength validation"""
    data = request.get_json()
    password = data.get('password', '')
    
    validation = validate_password_strength(password)
    return jsonify(validation)

@app.route('/api/validate-email', methods=['POST'])
def api_validate_email():

    """API endpoint for real-time email validation"""
    data = request.get_json()
    email = data.get('email', '').strip()
    
    validation = validate_email(email)
    return jsonify(validation)


if __name__ == "__main__":
    app.run(debug=True, threaded=False, use_reloader=False)