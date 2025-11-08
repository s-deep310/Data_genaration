# Standard libraries
import os
import json
import random
import datetime
import logging
import sqlite3

# Data science libraries
import numpy as np
import torch
import joblib
from safetensors.torch import load_file
from scipy.spatial.distance import cosine

# Scikit-learn modules
from sklearn.linear_model import LogisticRegression, LinearRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score

# Configure logging once here
logging.basicConfig(level=logging.INFO)
