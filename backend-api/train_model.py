import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from joblib import dump
import numpy as np

# --- PLACEHOLDER: Define simulated features and labels ---
def generate_placeholder_data(n_samples=1000):
    # Features (simplified): Length, Protocol (1=TCP, 2=UDP, 3=ICMP), Port_Entropy (0-1)
    data = {
        'length': np.random.randint(40, 1500, n_samples),
        'protocol_encoded': np.random.choice([1, 2, 3], n_samples),
        'port_entropy': np.random.rand(n_samples)
    }
    df = pd.DataFrame(data)
    
    # Simple rule for "Malicious" (e.g., small packets with high port entropy)
    df['is_malicious'] = ((df['length'] < 100) & (df['port_entropy'] > 0.8)).astype(int)
    
    # In a real project, this is where you'd load your KDD Cup 99 or UNSW-NB15 data
    return df

def train_model():
    print("Generating and training Random Forest model...")
    df = generate_placeholder_data()
    
    X = df[['length', 'protocol_encoded', 'port_entropy']]
    y = df['is_malicious']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Use Random Forest classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Save the trained model
    dump(model, 'random_forest_model.pkl')
    print("Model trained and saved as random_forest_model.pkl")

if __name__ == "__main__":
    train_model()