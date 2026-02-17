#!/bin/bash

# Agentic Network Security Monitor - Setup Script
# Author: Hiren Manani (Syracuse University)

echo "========================================================================"
echo "🚀 INITIALIZING AGENTIC NETWORK SECURITY MONITOR ENVIRONMENT"
echo "========================================================================"

# 1. Create directory structure
echo "📂 Creating project directories..."
mkdir -p data/raw_logs
mkdir -p config
mkdir -p dashboard
mkdir -p scripts
mkdir -p tests

# 2. Setup Virtual Environment
if [ ! -d ".venv" ]; then
    echo "🐍 Creating Python virtual environment..."
    python3 -m venv .venv
else
    echo "✓ Virtual environment already exists."
fi

# 3. Install Dependencies
echo "📦 Installing required packages from requirements.txt..."
source .venv/bin/activate
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "⚠️ requirements.txt not found! Installing base dependencies..."
    pip install pandas scikit-learn matplotlib seaborn sqlite3
fi

# 4. Initialize Configuration
echo "⚙️ Verifying configuration files..."
if [ ! -f "config/detection_rules.json" ]; then
    echo "Creating default detection_rules.json..."
    echo '{"port_scanning": {"threshold": 20, "window": 60}}' > config/detection_rules.json
fi

# 5. Data Preparation
echo "📊 Checking for training data..."
if [ ! -f "data/raw_logs/normal_traffic.csv" ]; then
    echo "⚠️ Warning: normal_traffic.csv missing. Run data generation scripts first."
fi

# 6. Database Reset (Optional)
if [ -f "data/incidents.db" ]; then
    read -p "Database detected. Wipe and restart? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm data/incidents.db
        echo "🗑️ Database cleared for fresh run."
    fi
fi

echo "========================================================================"
echo "✅ SETUP COMPLETE"
echo "To begin monitoring, run: source .venv/bin/activate && python3 src/main.py"
echo "========================================================================"