# Task 6 – Password Strength Evaluation

## Objective
To understand what makes a password strong by testing different passwords using:
- **Online Tool:** [https://passwordmeter.com](https://passwordmeter.com)
- **Offline Tool:** `pwtool.py` (custom password analyzer)

---

## 🧭 Hints / Mini Guide
1. Create multiple passwords with varying complexity.  
2. Use uppercase, lowercase, numbers, symbols, and length variations.  
3. Test each password on a password strength checker.  
4. Note scores and feedback from the tool.  
5. Identify best practices for creating strong passwords.  
6. Write down tips learned from the evaluation.  
7. Research common password attacks (brute force, dictionary).  
8. Summarize how password complexity affects security.  

**Outcome:** Understanding password security and best practices.

---

## Tools Used
- [passwordmeter.com](https://passwordmeter.com)
- Python 3 + `pwtool.py`
- Optional library: `zxcvbn`

---

## Screenshots (from passwordmeter.com)

### Weak Password Example
![Weak Password (123456)](./Screenshot%202025-10-28%20211236.png)

### Strong Password Example
![Strong Password (T!m3$@ndSp@ce2025)](./Screenshot%202025-10-28%20213229.png)

---

## Results from `pwtool.py`
*(Extracted from `results.txt`)*

```
============================================================
 pwtool.py — Password Analyzer & Custom Wordlist Generator  
             defensive testing / education only             
============================================================
Password analysis:
  Password: 123456
  Entropy: 15.93
  Score: Very weak
  Feedback:
   - Password is short — use 12+ characters for better security.
   - Add symbols to increase strength.
============================================================
Password analysis:
  Password: Password123
  Entropy: 51.5
  Score: Reasonable
  Feedback:
   - Add symbols to increase strength.
============================================================
Password analysis:
  Password: P@ssw0rd
  Entropy: 52.44
  Score: Reasonable
============================================================
Password analysis:
  Password: T@ndSp@ce2025
  Entropy: 79.21
  Score: Strong
  Feedback:
   - Password contains a year — years are common and predictable.
============================================================
Password analysis:
  Password: Ilovechocolatecake
  Entropy: 102.61
  Score: Very strong
  Feedback:
   - Add symbols to increase strength.
```

---

## Comparative Summary

| Password | Online Score | Local Entropy | Local Score | Overall Complexity |
|-----------|--------------|---------------|--------------|--------------------|
| 123456 | 4 % | 15.93 | Very Weak | Easily cracked |
| Password123 | 35 % | 51.5 | Reasonable | Moderate |
| P@ssw0rd | 65 % (approx) | 52.4 | Reasonable | Fair |
| T@ndSp@ce2025 | 100 % | 79.2 | Strong | Excellent |
| Ilovechocolatecake | 90 % (approx) | 102.6 | Very Strong | Passphrase quality |

---

## 🛡 Identify Best Practices for Creating Strong Passwords
- Use at least **12–16 characters** or more.  
- Combine **uppercase, lowercase, numbers, and special symbols**.  
- Avoid **dictionary words**, names, or birth years.  
- Create **unique passwords for each account**.  
- Use a **password manager** to store and generate complex passwords.  
- Prefer **passphrases** — e.g., `Blue!Mountain$Coffee2025` — memorable but complex.  
- Change passwords periodically and especially after a breach.

---

## 💡 Write Down Tips Learned from the Evaluation
- Password strength increases exponentially with **length**.  
- **Randomness** matters more than complexity alone.  
- **Symbols and mixed cases** significantly raise entropy.  
- **Avoid patterns** like “123” or “qwerty”.  
- **Passphrases** are practical alternatives to hard-to-remember strings.  
- Even a single weak password can compromise overall security.

---

## 🧨 Research Common Password Attacks
- **Brute Force Attack:** Tries every possible combination until it matches.  
- **Dictionary Attack:** Uses a list of common passwords (e.g., “password”, “123456”).  
- **Hybrid Attack:** Combines dictionary words with variations like “Password123!”.  
- **Phishing Attack:** Tricks users into revealing their password.  
- **Credential Stuffing:** Reuses stolen passwords on multiple sites.  

**Defense:** Use long, random passwords and enable **multi-factor authentication (MFA)** whenever possible.

---

## 📊 Summarize How Password Complexity Affects Security
- **Length:** Every extra character doubles or triples crack time.  
- **Character Variety:** Using all character types (Aa1!@) greatly expands the search space.  
- **Randomness:** Unpredictable combinations resist dictionary and hybrid attacks.  
- **Patterns:** Predictable sequences drastically reduce real security.  

**Example:**  
A simple 6-character lowercase password can be cracked in seconds,  
while a 14-character mixed password can take **billions of years** with brute force.

---

## 🧠 Key Learnings
- **Longer + Random + Mixed = Strong**.  
- Avoid common words, predictable patterns, or reused passwords.  
- Tools like `pwtool.py` help understand entropy and weak spots.  
- Passphrases combine security and memorability.  

---

## 🧩 Conclusion
Both tools confirm that **length, randomness, and character variety** are crucial for password security.  
A well-constructed passphrase or long, random password provides the best defense against brute-force and dictionary attacks.  

---

## 🏁 Outcome
Through this task, I learned how to:
- Analyze password strength using both online and offline tools.  
- Identify best practices for password creation.  
- Recognize different password attack types.  
- Understand how complexity directly improves security.  

**Final Understanding:**  
> Password strength isn’t just about symbols — it’s about being long, unique, and unpredictable.
---

### **Author**
- **Cybersecurity Intern – Task 6** 
- Your Name : VENI.J
  
