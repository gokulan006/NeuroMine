import os
from dotenv import load_dotenv
from langchain_community.vectorstores import FAISS
from tqdm import tqdm
from src.helper import load_split_documents, create_embedding_fnc
load_dotenv()
import pickle

os.environ['OPENAI_API_KEY']=os.getenv('OPENAI_API_KEY')

with open("documents.pkl", "rb") as f:
    documents = pickle.load(f)
 
embeddings=create_embedding_fnc()

texts = [d.page_content for d in documents]
metadatas = [d.metadata for d in documents]

 
 
all_text_embeddings = []
all_metas = []

batch_size = 100   
print("Total number of Text",len(texts))
for i in range(0, len(texts), batch_size):
    print("Current Batch",i)
    batch_texts = texts[i:i+batch_size]
    batch_metas = metadatas[i:i+batch_size]
    batch_vectors = embeddings.embed_documents(batch_texts)

     
    all_text_embeddings.extend(zip(batch_texts, batch_vectors))
    all_metas.extend(batch_metas)

# now build FAISS
faiss_db = FAISS.from_embeddings(
    text_embeddings=all_text_embeddings,
    embedding=embeddings,
    metadatas=all_metas
)

faiss_db.save_local("faiss_index")
