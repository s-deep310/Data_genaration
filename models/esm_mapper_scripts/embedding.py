import torch
import json
from safetensors.torch import load_file

class SimpleTokenizer:
    def __init__(self, vocab_file):
        self.token2idx = {}
        with open(vocab_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                token = line.strip()
                self.token2idx[token] = idx
        self.unk_token = "[UNK]"
        self.cls_token = "[CLS]"
        self.sep_token = "[SEP]"
        self.max_length = 512

    def tokenize(self, text):
        return text.lower().split()

    def convert_tokens_to_ids(self, tokens):
        return [self.token2idx.get(t, self.token2idx.get(self.unk_token, 0)) for t in tokens]

    def __call__(self, text):
        tokens = [self.cls_token] + self.tokenize(text)[:self.max_length-2] + [self.sep_token]
        input_ids = self.convert_tokens_to_ids(tokens)
        attention_mask = [1] * len(input_ids)
        pad_len = self.max_length - len(input_ids)
        input_ids += [0] * pad_len
        attention_mask += [0] * pad_len
        return {
            "input_ids": torch.tensor([input_ids], dtype=torch.long),
            "attention_mask": torch.tensor([attention_mask], dtype=torch.float)
        }

class SimpleBertModel(torch.nn.Module):
    def __init__(self, config):
        super().__init__()
        self.hidden_size = config.get("hidden_size", 768)
        self.dummy_linear = torch.nn.Linear(self.hidden_size, self.hidden_size)  # REPLACE with real model for prod

    def forward(self, input_ids, attention_mask):
        batch_size, seq_len = input_ids.shape
        device = input_ids.device
        hidden_size = self.dummy_linear.out_features
        embeddings = torch.randn(batch_size, seq_len, hidden_size, device=device)
        output = self.dummy_linear(embeddings)
        return (output,)

class BertEmbedder:
    def __init__(self, model_path, vocab_path, config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        self.model = SimpleBertModel(config)
        self.tokenizer = SimpleTokenizer(vocab_path)
        state_dict = load_file(model_path, device="cpu")
        self.model.load_state_dict(state_dict, strict=False)
        self.model.eval()

    def encode(self, text):
        inputs = self.tokenizer(text)
        with torch.no_grad():
            outputs = self.model(input_ids=inputs["input_ids"], attention_mask=inputs["attention_mask"])
        last_hidden_state = outputs[0]
        attention_mask = inputs["attention_mask"].unsqueeze(-1)
        masked = last_hidden_state * attention_mask
        summed = masked.sum(dim=1)
        counts = attention_mask.sum(dim=1).clamp(min=1e-9)
        mean_pooled = summed / counts
        return mean_pooled.squeeze().cpu().numpy()
