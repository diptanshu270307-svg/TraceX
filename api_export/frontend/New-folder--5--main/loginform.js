const container = document.querySelector('.container');
const registerBtn = document.querySelector('.register-btn-1');
const loginBtn = document.querySelector('.login-btn-1');

registerBtn.addEventListener('click',()=>{
    container.classList.add('active');
});

loginBtn.addEventListener('click',()=>{
    container.classList.remove('active');
});