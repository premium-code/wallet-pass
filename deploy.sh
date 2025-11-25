echo "1. Generating JSON from CSV..."
node convert.js

echo "2. Updating Database..."
# This renames the new output to your secret file
mv output.json bc7a3d75-ee17-4816-afe4-4ae2d20ad056.json

echo "3. Uploading to GitHub..."
git add .
git commit -m "Auto-update tickets"
git push origin main

echo "✅ DONE! Your site is updated."