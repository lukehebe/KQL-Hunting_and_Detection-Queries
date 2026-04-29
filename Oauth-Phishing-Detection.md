OAuth phishing (often called Consent Phishing) is highly effective even against PIV/CAC cards because it targets a different layer of the security stack. While PIV cards are the gold standard for Authentication (proving who you are), OAuth phishing targets Authorization (deciding what an app can do on your behalf).

```
EmailUrlInfo
| where Url startswith "https://login.microsoftonline.com/common/oauth2/v2.0/authorize" and Url has "prompt=none"
| join EmailEvents on NetworkMessageId
| where EmailDirection == "Inbound"
| where DeliveryAction <> "Blocked"
```
