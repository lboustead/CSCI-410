def load_log_file(path):
    try:
        with open(path, 'r') as f:
            return f.readlines()
    except Exception as e:
        print(f"Error: {e}")
        return []
