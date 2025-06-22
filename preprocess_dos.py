# preprocessing_api.py

import pandas as pd
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import joblib  # For loading saved scalers and median values

# --- 1. Define the Input Data Structure ---
# This tells FastAPI what kind of JSON data to expect from n8n.
# The field names here MUST match the names you set in your n8n "Edit Fields" node.
class Flow(BaseModel):
    # This list must contain ALL features you send from n8n for DoS preprocessing.
    dst_port: float
    protocol: float
    flow_duration: float
    tot_fwd_pkts: float
    tot_bwd_pkts: float
    totlen_fwd_pkts: float
    fwd_pkt_len_max: float
    fwd_pkt_len_std: float
    bwd_pkt_len_max: float
    bwd_pkt_len_min: float
    bwd_pkt_len_mean: float
    bwd_pkt_len_std: float
    flow_byts_s: float
    flow_pkts_s: float
    flow_iat_mean: float
    flow_iat_min: float
    bwd_iat_tot: float
    bwd_iat_mean: float
    bwd_iat_min: float
    fwd_psh_flags: float
    bwd_psh_flags: float
    fwd_urg_flags: float
    bwd_urg_flags: float
    fwd_header_len: float
    bwd_header_len: float
    fwd_pkts_s: float
    bwd_pkts_s: float
    fin_flag_cnt: float
    syn_flag_cnt: float
    down_up_ratio: float
    bwd_seg_size_avg: float
    fwd_byts_b_avg: float
    fwd_pkts_b_avg: float
    fwd_blk_rate_avg: float
    bwd_byts_b_avg: float
    bwd_pkts_b_avg: float
    bwd_blk_rate_avg: float
    init_fwd_win_byts: float
    init_bwd_win_byts: float
    fwd_seg_size_min: float

# --- 2. Load Your Saved Scalers and Median Values ---
# IMPORTANT: These files must be created and saved during your model training phase.
# They are essential for consistent preprocessing.
try:
    # Example: scaler = joblib.load('dos_scaler.pkl')
    # Example: median_values = joblib.load('dos_median_values.pkl')
    scaler = "placeholder_scaler" # Replace with joblib.load('your_dos_scaler.pkl')
    median_values = { # Replace with joblib.load('your_dos_medians.pkl')
        'flow_duration': 5000, 'tot_fwd_pkts': 5, 'tot_bwd_pkts': 3,
        'totlen_fwd_pkts': 200, 'fwd_pkt_len_max': 100, 'fwd_pkt_len_std': 20,
        'bwd_pkt_len_max': 150, 'bwd_pkt_len_min': 0, 'bwd_pkt_len_mean': 75,
        'bwd_pkt_len_std': 30, 'flow_pkts_s': 2000, 'flow_iat_mean': 2500,
        'flow_iat_min': 10, 'bwd_iat_tot': 4000, 'bwd_iat_mean': 2000,
        'bwd_iat_min': 5,
    }
    # This list must contain the feature names in the EXACT order your scaler expects them.
    # It should also be saved from your training script.
    # scaler_cols = joblib.load('scaler_columns.pkl')
    scaler_cols = list(Flow.__fields__.keys()) # Using all fields as a placeholder
except FileNotFoundError:
    print("Warning: Scaler or median value files not found. Using placeholder values.")
    scaler = "placeholder_scaler"
    median_values = {
        'flow_duration': 5000, 'tot_fwd_pkts': 5, 'tot_bwd_pkts': 3,
        'totlen_fwd_pkts': 200, 'fwd_pkt_len_max': 100, 'fwd_pkt_len_std': 20,
        'bwd_pkt_len_max': 150, 'bwd_pkt_len_min': 0, 'bwd_pkt_len_mean': 75,
        'bwd_pkt_len_std': 30, 'flow_pkts_s': 2000, 'flow_iat_mean': 2500,
        'flow_iat_min': 10, 'bwd_iat_tot': 4000, 'bwd_iat_mean': 2000,
        'bwd_iat_min': 5,
    }
    scaler_cols = list(Flow.__fields__.keys())

# --- 3. Create the FastAPI Application ---
app = FastAPI()

# --- 4. Define the Preprocessing Endpoint ---
@app.post("/preprocess/dos")
async def preprocess_dos_data(data: List[Flow]):
    if not data:
        raise HTTPException(status_code=400, detail="No data provided")

    try:
        # Convert the list of Pydantic models to a Pandas DataFrame
        input_df = pd.DataFrame([flow.dict() for flow in data])
        
        # --- Start of Preprocessing Logic ---

        # === GLOBAL CLEANING ===
        df = input_df.copy() # Work on a copy to avoid modifying the original input
        df.replace([np.inf, -np.inf], np.nan, inplace=True)

        # === FEATURE-WISE IMPUTATION ===
        # Impute with MEDIAN
        median_impute_cols = [
            'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts',
            'fwd_pkt_len_max', 'fwd_pkt_len_std', 'bwd_pkt_len_max', 'bwd_pkt_len_min',
            'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'flow_pkts_s', 'flow_iat_mean',
            'flow_iat_min', 'bwd_iat_tot', 'bwd_iat_mean', 'bwd_iat_min'
        ]
        for col in median_impute_cols:
            if col in df.columns:
                df[col].fillna(median_values.get(col, 0), inplace=True)

        # Impute with ZERO
        zero_impute_cols = [
            'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
            'fin_flag_cnt', 'syn_flag_cnt', 'down_up_ratio', 'fwd_header_len',
            'bwd_header_len', 'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'fwd_blk_rate_avg',
            'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'bwd_blk_rate_avg'
        ]
        for col in zero_impute_cols:
            if col in df.columns:
                df[col].fillna(0, inplace=True)
                
        # Impute using DERIVED FORMULAS
        epsilon = 1e-9 # Add a small number to prevent division by zero
        if 'fwd_pkts_s' in df.columns:
            # Assuming flow_duration is in microseconds
            df['fwd_pkts_s'].fillna(df['tot_fwd_pkts'] / (df['flow_duration'] / 1_000_000 + epsilon), inplace=True)
        if 'bwd_pkts_s' in df.columns:
            df['bwd_pkts_s'].fillna(df['tot_bwd_pkts'] / (df['flow_duration'] / 1_000_000 + epsilon), inplace=True)
        if 'bwd_seg_size_avg' in df.columns:
            df['bwd_seg_size_avg'].fillna(df['totlen_bwd_pkts'] / (df['tot_bwd_pkts'] + epsilon), inplace=True)

        # Final fallback fill for any remaining NaNs
        df.fillna(0, inplace=True)
        
        # === NORMALIZATION ===
        # Use the scaler that was FIT on your TRAINING data.
        if scaler != "placeholder_scaler":
            # Use only .transform() here
            df_scaled_values = scaler.transform(df[scaler_cols])
            # Create a new DataFrame with the scaled values and correct column names
            processed_df = pd.DataFrame(df_scaled_values, columns=scaler_cols, index=df.index)
        else:
            print("Warning: Using placeholder scaler. Data is not being normalized.")
            processed_df = df # If no scaler, just use the imputed data

        # Final check to ensure data is clean
        assert processed_df.notna().all().all(), "NaNs still exist after preprocessing"
        assert np.isfinite(processed_df.to_numpy()).all(), "Infinite values still exist after preprocessing"
        
        # --- End of Preprocessing Logic ---

        # Convert the final preprocessed DataFrame to a list of JSON objects to send back
        response = processed_df.to_dict(orient='records')
        
        return response

    except Exception as e:
        # Log the error and return a detailed error message to n8n
        print(f"An error occurred during preprocessing: {e}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error during preprocessing: {e}")

# --- 5. (Optional) A simple root endpoint to check if the API is running ---
@app.get("/")
def read_root():
    return {"status": "Preprocessing API for DoS is running"}