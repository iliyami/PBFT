import string
class Shared:
    byzantines = []
    alphabet_dict = {letter: i for i, letter in enumerate(string.ascii_uppercase[:10], start=1)}
    number_to_label = {i: letter for i, letter in enumerate(string.ascii_uppercase[:10], start=1)}
    
    REQUEST_TYPE_BALANCE = "balance"

    def get_alphabet_for_number(number):
        inverse_dict = {v: k for k, v in Shared.alphabet_dict.items()}
        label = inverse_dict.get(number, None)
        return label
    
    def get_number_for_alphabet(letter):
        return Shared.alphabet_dict.get(letter.upper(), None)
    
    def convert_labels_to_keys(label_string):
        labels = label_string.strip("()").replace(" ", "").split(",")

        converted = [str(Shared.alphabet_dict[label]) if label in Shared.alphabet_dict else label for label in labels]

        return f"({', '.join(converted)})"