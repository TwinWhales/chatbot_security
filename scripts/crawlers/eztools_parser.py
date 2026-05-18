import os
import json
import glob
import re

# Constants
SOURCE_DIR = r"c:\Users\user\Desktop\Temp\data\raw\Yechan\EZToolsManuals\manuscript"
TARGET_DIR = r"c:\Users\user\Desktop\Temp\data\raw\Yechan\eztools_json"
BASE_URL = "https://github.com/EZToolsManuals/EZToolsManuals/blob/main/manuscript/"

# Files to exclude (metadata/book publishing files rather than tool manuals)
EXCLUDE_FILES = {
    "Book.txt", "ToolTemplate.txt", "errata.txt", "samplecomment.txt",
    "sectionCLI.txt", "sectionGUI.txt", "todo.txt", "updatenotifications.txt"
}

def clean_text(text):
    """Cleans Leanpub Markua tags, HTML comments, markdown images, and unnecessary newlines."""
    # Remove Leanpub specific tags
    text = re.sub(r'\{pagebreak\}', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\{line-numbers:[^}]*\}', '', text, flags=re.IGNORECASE)
    
    # 1. Markua warning/info/error blocks (W|, I|, E|, etc.)
    text = re.sub(r'^[A-Z]\| ', '', text, flags=re.MULTILINE)
    
    # 2. Header anchors like {#anchor-name}
    text = re.sub(r'\{#[^}]+\}', '', text)
    
    # 3. Markdown image links ![alt](path)
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
    
    # 4. Remove HTML comments
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    
    # 5. Normalize multiple newlines to double newlines
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()

def main():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    txt_files = glob.glob(os.path.join(SOURCE_DIR, "*.txt"))
    count = 0

    for file_path in txt_files:
        filename = os.path.basename(file_path)
        
        if filename in EXCLUDE_FILES:
            continue

        tool_name = filename.replace(".txt", "")

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = clean_text(f.read())

        data = {
            "url": BASE_URL + filename,
            "title": f"EZ Tools - {tool_name}",
            "source": "EZToolsManuals",
            "content": content
        }

        target_file = os.path.join(TARGET_DIR, f"{tool_name}.json")
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        
        count += 1
        print(f"Saved: {target_file}")

    print(f"\nSuccessfully converted {count} EZ Tools manuals to JSON format.")

if __name__ == "__main__":
    main()
