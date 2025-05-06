from input_handler import load_log_file
from analyzer import analyze_log
from pattern_detector import detect_known_patterns
from prototype_detector import detect_prototype_patterns
from attack_decision import determine_attack

def main():
    path = input("Enter path to log file: ")
    log_lines = load_log_file(path)
    parsed_data = analyze_log(log_lines)

    known_results = detect_known_patterns(parsed_data)
    proto_results = detect_prototype_patterns(parsed_data)

    attack_report = determine_attack(known_results, proto_results)

    print("\n--- Final Report ---")
    for entry in attack_report:
        print(entry)

if __name__ == "__main__":
    main()
