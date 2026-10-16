# Void - training code

Scripts used to train the models behind the live page.

- `crawl.py` - collects legitimate URLs: takes 2,500 random domains from the Tranco top list, fetches each homepage and keeps up to 14 absolute links per page.
- `feats.py` - 29 URL-only features (length, dots, hyphens, digits, entropy, @, IP, https, suspicious words, ...). The same logic is ported to `engine.js` on the page.
- `train.py` - builds the dataset, trains Logistic Regression, Decision Tree, Random Forest, linear SVM, small neural net (MLP) and XGBoost, evaluates, and exports `model.json`.

## Data
- Phishing: PhishTank verified URLs (data.phishtank.com/data/online-valid.csv, downloaded 16 Oct 2026). 20,000 sampled.
- Legitimate: 14,736 links from `crawl.py`.
- 34,736 unique URLs after dedupe.
- Extra recall check on 3,000 held-out PhishTank URLs and 298 OpenPhish URLs (openphish.com/feed.txt) not used in training.
- The UCI PhiUSIIL dataset was tried and dropped: all its legitimate URLs are bare "https://www.site.com" homepages, so models learn that artifact instead of phishing patterns.

## Split
80/20. Main result: grouped by registered domain (test domains never seen in training). A plain random split is also reported and is more optimistic.

## Results (domain-grouped test set, 5,345 URLs)
| Model | Acc | Prec | Rec | F1 | AUC |
|---|---|---|---|---|---|
| Logistic Regression | 0.797 | 0.752 | 0.807 | 0.778 | 0.890 |
| Decision Tree | 0.846 | 0.865 | 0.773 | 0.816 | 0.871 |
| Random Forest | 0.878 | 0.896 | 0.818 | 0.855 | 0.944 |
| SVM (linear) | 0.807 | 0.763 | 0.818 | 0.789 | 0.892 |
| Neural Net (MLP) | 0.869 | 0.850 | 0.853 | 0.852 | 0.933 |
| XGBoost | 0.892 | 0.882 | 0.872 | 0.877 | 0.947 |

Limits: URL text only, legitimate set comes from popular-site homepages, so real-world accuracy can be lower.
