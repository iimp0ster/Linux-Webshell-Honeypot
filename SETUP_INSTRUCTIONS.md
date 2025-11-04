# Setup Instructions

## Quick GitHub Upload

### Step 1: Create GitHub Repository
1. Go to https://github.com/new
2. Name: `sigma-honeypot-lab`
3. Description: `Detection engineering lab for learning Sigma rules with real attacks`
4. **Public** repository
5. **DO NOT** initialize with README (we have one)
6. Click "Create repository"

### Step 2: Upload From This Directory

```bash
cd /home/claude/sigma-honeypot-lab

# Initialize git
git init
git add .
git commit -m "Initial commit: Complete Sigma Honeypot Lab"

# Add your GitHub repo (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/sigma-honeypot-lab.git

# Push to GitHub
git branch -M main
git push -u origin main
```

### Step 3: Update URLs
After pushing, update these files to replace YOUR_USERNAME with your actual GitHub username:
- README.md
- install.sh

Do a find/replace:
```bash
# Replace YOUR_USERNAME with your actual username
find . -type f -name "*.md" -o -name "*.sh" | xargs sed -i 's/YOUR_USERNAME/your-actual-username/g'

# Commit the changes
git add .
git commit -m "Update username in URLs"
git push
```

### Step 4: Test Installation
On a fresh Ubuntu server:
```bash
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/install.sh | sudo bash
```

## Files Still Needed

Create these files manually after pushing initial version:

1. **dashboard/sigma_dashboard.py** - Streamlit dashboard code
2. **dashboard/Dockerfile** - Docker image for dashboard
3. **sample_webshells/** - 4 PHP webshell examples
4. **sigma_rules/** - 3 example Sigma rules
5. **docs/** - 4 documentation files

I'll create these in the next steps!
