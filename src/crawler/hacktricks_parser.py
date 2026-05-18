import os
import json
import glob
import re

# Constants
SOURCE_DIR = r"c:\Users\user\Desktop\Temp\data\raw\Yechan\hacktricks"
TARGET_DIR = r"c:\Users\user\Desktop\Temp\data\raw\Yechan\hacktricks_json"
BASE_URL = "https://book.hacktricks.xyz/"

def clean_text(text):
    """Cleans markdown images and HTML comments."""
    # Remove HTML comments
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    
    # Remove Markdown image links ![alt](path)
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
    
    # Normalize multiple newlines to double newlines
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()

def main():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    md_files = glob.glob(os.path.join(SOURCE_DIR, "**", "*.md"), recursive=True)
    count = 0

    for file_path in md_files:
        # Calculate relative path to construct URL and category
        rel_path = os.path.relpath(file_path, SOURCE_DIR)
        
        # Replace Windows backslashes with forward slashes for URL
        url_path = rel_path.replace("\\", "/").replace(".md", "")
        url = BASE_URL + url_path

        # Category can be the parent folder name
        parent_dir = os.path.dirname(rel_path)
        category = parent_dir.replace("\\", "/") if parent_dir else "Root"
        
        filename = os.path.basename(file_path)
        title = filename.replace(".md", "")

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = clean_text(f.read())
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            continue
            
        if not content:
            continue # Skip empty files

        data = {
            "url": url,
            "title": title,
            "category": category,
            "source": "HackTricks",
            "content": content
        }

        # Create a safe filename (flattening the directory structure to avoid deep nesting, or keeping it)
        # We will flatten it but prefix with category to avoid name collisions
        safe_category = category.replace("/", "_")
        if safe_category == "Root":
            safe_filename = f"{title}.json"
        else:
            safe_filename = f"{safe_category}_{title}.json"
            
        target_file = os.path.join(TARGET_DIR, safe_filename)
        
        try:
            with open(target_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            count += 1
        except Exception as e:
            print(f"Error writing {target_file}: {e}")

    print(f"\nSuccessfully converted {count} HackTricks markdown files to JSON format.")

if __name__ == "__main__":
    main()
