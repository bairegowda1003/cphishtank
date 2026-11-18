# Data cleaning report

Final training set: **19,292** messages (+3,000 in external_test.csv).

## Class x channel
| class | channel | count | median chars |
|---|---|---|---|
| legitimate | email | 3,908 | 501 |
| legitimate | sms | 9,549 | 56 |
| phishing | email | 3,236 | 615 |
| phishing | sms | 879 | 146 |
| suspicious | email | 1,195 | 1065 |
| suspicious | sms | 525 | 148 |

## Cleaning funnel per source
| source | raw | dropped: down-sampled | dropped: empty/too short | dropped: exact duplicate | dropped: mostly non-text | dropped: near duplicate | dropped: not English | final |
|---|---|---|---|---|---|---|---|---|
| nus_sms | 55,801 | 25,050 | 9,208 | 6,021 | 181 | 82 | 10,259 | 5,000 |
| phishing_pot | 12,271 | 0 | 851 | 1,694 | 28 | 691 | 5,805 | 3,202 |
| smishtank | 1,055 | 0 | 22 | 64 | 4 | 76 | 96 | 793 |
| spamassassin | 6,046 | 0 | 29 | 207 | 24 | 432 | 258 | 5,096 |
| spamdam | 76,577 | 0 | 39,475 | 568 | 360 | 1,047 | 23,657 | 13,085 |
| synthetic_bec | 800 | 275 | 0 | 237 | 0 | 168 | 0 | 120 |
| synthetic_legit | 4,000 | 665 | 0 | 2,007 | 0 | 628 | 0 | 700 |
| uci_sms | 5,574 | 0 | 82 | 392 | 6 | 52 | 661 | 4,381 |
