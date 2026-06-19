/**
 * download.js — handles the password modal on the download page
 * Shows automatically when the file is password-protected.
 */

const modal       = document.getElementById('passwordModal');
const closeBtn    = document.getElementById('modalClose');
const form        = document.getElementById('passwordForm');
const errorDiv    = document.getElementById('modalError');
const passInput   = document.getElementById('modalPassword');
const token       = document.getElementById('modalToken').value;

/* Close modal when × is clicked */
closeBtn.addEventListener('click', () => modal.style.display = 'none');

/* Close modal when clicking the dark backdrop (not the card) */
modal.addEventListener('click', e => {
    if (e.target === modal) modal.style.display = 'none';
});

/* Handle password form submit */
form.addEventListener('submit', function(e) {
    e.preventDefault();
    errorDiv.style.display = 'none';

    const formData = new FormData();
    formData.append('token',    token);
    formData.append('password', passInput.value);
    formData.append('action',   'download');

    /* POST to verify.php — returns {success: true} or {error: "..."} */
    fetch('verify.php', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                /* Password correct → redirect to serve the file */
                window.location.href = '?token=' + encodeURIComponent(token) + '&download=1';
            } else {
                /* Wrong password → show error, clear field */
                errorDiv.textContent  = data.error || 'Wrong password.';
                errorDiv.style.display = 'block';
                passInput.value = '';
                passInput.focus();
            }
        })
        .catch(() => {
            errorDiv.textContent   = 'An error occurred. Please try again.';
            errorDiv.style.display = 'block';
        });
});
