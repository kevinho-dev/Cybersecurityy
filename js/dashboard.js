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

/* ── File upload preview ─────────────────────────────────────
   Shows filename, size, and a thumbnail (for images) the moment
   a file is selected in the upload form. Has a × button to clear
   the selection before submitting.
*/
const fileInput      = document.getElementById('fileToUpload');
const preview        = document.getElementById('filePreview');
const previewThumb    = document.getElementById('filePreviewThumb');
const previewName     = document.getElementById('filePreviewName');
const previewSize     = document.getElementById('filePreviewSize');
const previewRemove   = document.getElementById('filePreviewRemove');

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

if (fileInput) {
    fileInput.addEventListener('change', function () {
        const file = fileInput.files[0];

        if (!file) {
            preview.style.display = 'none';
            return;
        }

        previewName.textContent = file.name;
        previewSize.textContent = formatFileSize(file.size);

        if (file.type.startsWith('image/')) {
            previewThumb.innerHTML = '';
            const img = document.createElement('img');
            img.src = URL.createObjectURL(file);
            previewThumb.appendChild(img);
        } else {
            previewThumb.innerHTML = '📄';
        }

        preview.style.display = 'flex';
    });

    previewRemove.addEventListener('click', function () {
        fileInput.value = '';
        preview.style.display = 'none';
    });
}