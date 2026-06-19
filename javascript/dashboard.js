/**
 * dashboard.js — password modal logic for the dashboard (index.php)
 * Handles both "Share link" (copies URL) and "Download" (serves file).
 */

const modal       = document.getElementById('passwordModal');
const closeBtn    = document.getElementById('modalClose');
const form        = document.getElementById('passwordForm');
const tokenInput  = document.getElementById('modalToken');
const actionInput = document.getElementById('modalAction');
const fileLabel   = document.getElementById('modalFilename');
const errorDiv    = document.getElementById('modalError');
const passInput   = document.getElementById('modalPassword');

/* Open modal when "Share link" or "Download" button is clicked */
document.querySelectorAll('.action-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        /* Fill modal fields from the button's data attributes */
        tokenInput.value      = this.dataset.token;
        actionInput.value     = this.dataset.action;
        fileLabel.textContent = this.dataset.filename;

        /* Reset state */
        errorDiv.style.display = 'none';
        passInput.value = '';

        modal.style.display = 'flex';
        passInput.focus();
    });
});

/* Close modal: × button */
closeBtn.addEventListener('click', () => modal.style.display = 'none');

/* Close modal: click on backdrop */
modal.addEventListener('click', e => {
    if (e.target === modal) modal.style.display = 'none';
});

/* Close modal: Escape key */
document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && modal.style.display === 'flex') modal.style.display = 'none';
});

/* Handle password submit */
form.addEventListener('submit', function(e) {
    e.preventDefault();
    errorDiv.style.display = 'none';

    const token  = tokenInput.value;
    const action = actionInput.value;

    const formData = new FormData();
    formData.append('token',    token);
    formData.append('password', passInput.value);
    formData.append('action',   action);

    /* POST credentials to verify.php (in /php/ relative to root) */
    fetch('php/verify.php', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                if (action === 'download') {
                    /* Password correct → trigger file download */
                    window.location.href = 'php/download.php?token=' + encodeURIComponent(token) + '&direct=1';
                } else if (action === 'share') {
                    /* Build share URL and copy to clipboard */
                    const url = window.location.origin
                        + window.location.pathname.replace(/\/index\.php$/, '').replace(/\/$/, '')
                        + '/php/download.php?token=' + encodeURIComponent(token);

                    navigator.clipboard.writeText(url)
                        .then(() => { alert('Share link copied to clipboard!'); modal.style.display = 'none'; })
                        .catch(() => { alert('Could not copy. Share link:\n' + url); modal.style.display = 'none'; });
                }
            } else {
                /* Wrong password */
                errorDiv.textContent   = data.error || 'Wrong password.';
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
