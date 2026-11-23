# AI Usage Disclosure

## AI Tools Used
* **Gemini:** Used as a coding assistant and editor throughout development and documentation.

## What I Used It For
* **Shannon Entropy Implementation:** Helped me understand and write the `get_entropy()` function using Python's `math.log2` after I learned about using character randomness to catch scrambled phishing URLs.
* **Test Dataset Generation:** Once, I created a good amount of test I got it to help me create some fake phishing URLs alongside legitimate URLs to build my 100-URL benchmark list.
* **Code Review & Debugging:** Once I created my scoring engine, thresholds, and evaluation metrics, I used AI to double-check my logic for bugs, edge cases, and alignment with my target goals (`Recall >= 80%` and `FPR <= 15%`).

## Files and Sections Assisted
* **`url_scorer.py`:** Assistance was limited to the `get_entropy()` helper function, generating the 100 labeled URLs in `data`, and reviewing my existing scoring and evaluation code. All the rules, point weights, risk thresholds, metric calculations, and the interactive CLI loop were written by me.

## How I Verified the Output
* **Checked the Test Data Labels:** Looked through the generated 100-URL dataset myself to make sure all 50 phishing links and 50 legitimate links were actually labeled correctly (`1` vs. `0`) and didn't include real malicious sites.
* **Checked the Code Output:** Ran the script and watched the outputs to verify that the entropy function and rules were scoring links properly, flagging the right things, and printing out the expected results.
* **Reviewed the Writing:** Read over all the drafted documentation and report sections to make sure everything was accurate to my project and sounded like me.