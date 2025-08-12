import streamlit as st
from cryptography.fernet import Fernet
import random
import string

# 🔑 암호화 키 생성 또는 불러오기
def load_or_create_key():
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

# 🔒 비밀번호 암호화 후 저장
def encrypt_and_save(service, username, password, fernet):
    encrypted = fernet.encrypt(password.encode()).decode()
    with open("passwords.enc", "a") as file:
        file.write(f"{service}|{username}|{encrypted}\n")

# 🔓 암호화된 비밀번호 복호화 및 출력
def load_and_decrypt(fernet):
    try:
        with open("passwords.enc", "r") as file:
            data = []
            for line in file:
                try:
                    service, username, encrypted_pw = line.strip().split("|")
                    decrypted_pw = fernet.decrypt(encrypted_pw.encode()).decode()
                    data.append({
                        "서비스": service,
                        "사용자명": username,
                        "비밀번호": decrypted_pw
                    })
                except Exception:
                    continue
            return data
    except FileNotFoundError:
        return []

# 🔐 랜덤 비밀번호 생성기
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# 🔁 앱 실행 흐름
st.set_page_config(page_title="비밀번호 관리자", page_icon="🔐")
st.title("🔐 비밀번호 암호화 저장소")

key = load_or_create_key()
fernet = Fernet(key)

# 📝 입력 폼
with st.form("pw_form"):
    service = st.text_input("서비스 이름")
    username = st.text_input("사용자 이름")

    st.subheader("🔐 비밀번호 입력 또는 생성")

    if "generated_password" not in st.session_state:
        st.session_state["generated_password"] = ""

    # 비밀번호 생성 버튼
    if st.form_submit_button("🔄 랜덤 비밀번호 생성"):
        st.session_state["generated_password"] = generate_random_password()

    # 비밀번호 입력창
    password = st.text_input("비밀번호 입력", type="password", value=st.session_state["generated_password"])

    # 저장 버튼
    save_submitted = st.form_submit_button("💾 저장하기")
    if save_submitted:
        if service and username and password:
            encrypt_and_save(service, username, password, fernet)
            st.success("✅ 암호화된 비밀번호가 저장되었습니다.")
            st.session_state["generated_password"] = ""  # 저장 후 초기화
        else:
            st.warning("⚠️ 모든 항목을 입력해 주세요.")

# 📄 저장된 비밀번호 표시
st.subheader("📄 저장된 비밀번호 목록")
data = load_and_decrypt(fernet)
if data:
    st.table(data)
else:
    st.info("아직 저장된 비밀번호가 없습니다.")
