import os
import json

def map_folder_structure(folder_path):
    folder_dict = {}

    for root, dirs, files in os.walk(folder_path):
        # Filter out directories that start with '__'
        dirs[:] = [dir_name for dir_name in dirs if not (
            dir_name.startswith('__') or 
            dir_name.startswith('.') or 
            'htmlcov' in dir_name
        )]

        # Build the folder structure as a dictionary
        rel_path = os.path.relpath(root, folder_path)
        current_folder = folder_dict
        if rel_path != '.':
            for part in rel_path.split(os.sep):
                if part not in current_folder or not isinstance(current_folder[part], dict):
                    current_folder[part] = {}
                current_folder = current_folder[part]

        # Add files to the folder dictionary, ignoring files starting with '__'
        file_list = [file_name for file_name in files if not (
            file_name.startswith('__') or
            file_name == os.path.basename(__file__) or
            file_name == 'folder_structure.json'
        )]
        if file_list:
            current_folder.setdefault('files', []).extend(file_list)

    return folder_dict
def main():
    folder_path = input("Enter the path of the folder to map: ").strip()
    if not os.path.exists(folder_path):
        print("The specified folder does not exist.")
        return

    folder_dict = map_folder_structure(folder_path)

    # Write the output to a JSON file
    output_file = 'folder_structure.json'
    with open(output_file, 'w') as f:
        json.dump(folder_dict, f, indent=4)

    print(f"Folder structure saved to {output_file}")

if __name__ == "__main__":
    main()