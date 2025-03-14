import re
import secrets
import string
import streamlit as st

# List of commonly used weak passwords
COMMON_PASSWORDS = {"password", "123456", "qwerty", "abc123", "password123", "admin", "letmein"}

def check_password_strength(password):
    """Checks password strength and returns feedback."""
    score = 0
    feedback = []

    # Check if password is in the blacklist
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("❌ Weak Password - It's too common. Choose a more secure one.")
        return score, feedback

    # Length Check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password must be at least 8 characters long.")

    # Upper & Lower Case Check
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Password must contain at least one uppercase and one lowercase letter.")

    # Digit Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Password must contain at least one digit.")

    # Special Character Check
    if re.search(r"[!@#$%^&*]", password):
        score += 1
    else:
        feedback.append("❌ Password must contain at least one special character.")

    return score, feedback

def generate_strong_password(length=12):
    """Generates a strong random password."""
    if length < 8:
        raise ValueError("Password length should be at least 8 characters.")

    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = "!@#$%^&*"  # Limited to commonly used special characters

    # Ensure at least one of each type
    all_chars = uppercase + lowercase + digits + special_chars
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special_chars)
    ]

    # Fill remaining characters randomly
    password += [secrets.choice(all_chars) for _ in range(length - 4)]

    # Shuffle to avoid patterns
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)

# ---------------- STREAMLIT APP ---------------- #
st.title("🔐 Password Strength Checker")

st.info("""
🔔 **Password Guidelines:**  
To ensure a **strong and secure password**, please follow these rules:  
✅ Must be **at least 8 characters long**  
✅ Include **both uppercase (A-Z) and lowercase (a-z) letters**  
✅ Include **at least one number (0-9)**  
✅ Include **at least one special character (!@#$%^&*)**  
❌ Avoid using common passwords like `"password123"`, `"123456"`, or `"qwerty"`  

💡 **Tip:** Use a mix of letters, numbers, and symbols to create a strong password!
""")


# Password Input Field
password = st.text_input("Enter your password:", type="password")

if password:
    score, feedback = check_password_strength(password)

    # Display feedback messages
    for msg in feedback:
        st.warning(msg)

    # Password Strength Rating
    if score == 4:
        st.success("✅ Strong Password!")
    elif score == 3:
        st.info("⚠️ Moderate Password - Consider adding more security features.")
    else:
        st.error("❌ Weak Password - Improve it using the suggestions above.")

# Generate Strong Password Button
if st.button("Generate Strong Password"):
    strong_pass = generate_strong_password(12)
    st.success(f"🔑 Suggested Strong Password: `{strong_pass}`")

        


