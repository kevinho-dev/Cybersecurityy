/**
 * app.js — All client-side JavaScript for the application.
 *
 * This file handles four independent features:
 *   1. The password modal (pop-up dialog used on the dashboard and download page)
 *   2. Dashboard action buttons (Share / Download / Share-with-user trigger modals)
 *   3. File upload preview (shows the selected file before submitting)
 *   4. Share-with-user modal (sends a file to another registered user)
 *
 * We wait for DOMContentLoaded before running, which guarantees that all HTML
 * elements exist before we try to find them.
 */
document.addEventListener('DOMContentLoaded', () => {

    // Remove ?link= from the URL bar after a successful upload redirect,
    // so refreshing doesn't re-show the share link box.
    if (window.location.search.includes('link=')) {
        history.replaceState(null, '', window.location.pathname);
    }

    const csrf = document.querySelector('meta[name="csrf-token"]')?.content ?? '';

    const modal = document.getElementById('passwordModal');

    if (modal) initModal(modal, csrf);
    initDashboardButtons(modal, csrf);
    initShareUserModal(csrf);
    initFilePreview();
});


// ─────────────────────────────────────────────────────────────────────────────
// 1. PASSWORD MODAL
// ─────────────────────────────────────────────────────────────────────────────

function initModal(modal, csrf) {
    const closeBtn  = document.getElementById('modalClose');
    const form      = document.getElementById('passwordForm');
    const errorDiv  = document.getElementById('modalError');
    const passInput = document.getElementById('modalPassword');

    if (closeBtn) closeBtn.onclick = () => closeModal(modal);
    modal.addEventListener('click', e => {
        if (e.target === modal) closeModal(modal);
    });
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && modal.style.display === 'flex') closeModal(modal);
        });

            if (!form) return;

            form.onsubmit = e => {
                e.preventDefault();
                errorDiv.style.display = 'none';

                const action = modal.dataset.action ?? 'download';

                const fd = new FormData();
                fd.append('token',      modal.dataset.token);
                fd.append('password',   passInput.value);
                fd.append('action',     action);
                fd.append('csrf_token', csrf);

                fetch(modal.dataset.verifyUrl, { method: 'POST', body: fd })
                .then(response => {
                    if (!response.ok) throw new Error('Server error');
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        if (action === 'share') {
                            const base = window.location.origin
                            + window.location.pathname.replace(/\/(index\.php)?$/, '');
                            const url  = `${base}/php/download.php?token=${encodeURIComponent(modal.dataset.token)}`;

                            navigator.clipboard.writeText(url)
                            .then(()  => alert('Copied!'))
                            .catch(() => alert('Link:\n' + url));

                            closeModal(modal);
                        } else {
                            window.location.href = modal.dataset.successUrl
                            .replace('{token}', encodeURIComponent(modal.dataset.token));
                        }
                    } else {
                        errorDiv.textContent   = data.error ?? 'Error';
                        errorDiv.style.display = 'block';
                        passInput.value        = '';
                        passInput.focus();
                    }
                })
                .catch(() => {
                    errorDiv.textContent   = 'Network error.';
                    errorDiv.style.display = 'block';
                });
            };
}

function openModal(modal) {
    modal.style.display = 'flex';
}

function closeModal(modal) {
    modal.style.display = 'none';
}


// ─────────────────────────────────────────────────────────────────────────────
// 2. DASHBOARD ACTION BUTTONS
// ─────────────────────────────────────────────────────────────────────────────

function initDashboardButtons(modal, csrf) {
    document.querySelectorAll('.action-btn').forEach(button => {
        button.onclick = function () {
            const action = this.dataset.action;

            if (action === 'share_with_user') {
                // Open the share-with-user modal instead of the password modal.
                const shareModal = document.getElementById('shareUserModal');
                if (!shareModal) return;
                shareModal.dataset.token = this.dataset.token;
                document.getElementById('shareUserFilename').textContent = this.dataset.filename;
                document.getElementById('shareUserInput').value           = '';
                document.getElementById('shareUserError').style.display   = 'none';
                document.getElementById('shareUserSuccess').style.display = 'none';
                shareModal.style.display = 'flex';
                document.getElementById('shareUserInput').focus();
                return;
            }

            if (!modal) return;
            // Load this button's file info into the password modal.
            modal.dataset.token  = this.dataset.token;
            modal.dataset.action = action;

            document.getElementById('modalFilename').textContent = this.dataset.filename;
            document.getElementById('modalPassword').value       = '';
            document.getElementById('modalError').style.display  = 'none';

            openModal(modal);
            document.getElementById('modalPassword').focus();
        };
    });
}


// ─────────────────────────────────────────────────────────────────────────────
// 3. FILE UPLOAD PREVIEW
// ─────────────────────────────────────────────────────────────────────────────

function initFilePreview() {
    const fileInput = document.getElementById('fileToUpload');
    if (!fileInput) return;

    const preview      = document.getElementById('filePreview');
    const previewThumb = document.getElementById('filePreviewThumb');
    const previewName  = document.getElementById('filePreviewName');
    const previewSize  = document.getElementById('filePreviewSize');
    const removeBtn    = document.getElementById('filePreviewRemove');

    fileInput.onchange = () => {
        const file = fileInput.files[0];
        if (!file) { preview.style.display = 'none'; return; }

        previewName.textContent = file.name;
        previewSize.textContent = formatFileSize(file.size);

        if (file.type.startsWith('image/')) {
            previewThumb.innerHTML = '';
            const img = document.createElement('img');
            img.src   = URL.createObjectURL(file);
            previewThumb.appendChild(img);
        } else {
            previewThumb.innerHTML = '📄';
        }

        preview.style.display = 'flex';
    };

    removeBtn.onclick = () => {
        fileInput.value       = '';
        preview.style.display = 'none';
    };
}

function formatFileSize(bytes) {
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1_048_576)  return (bytes / 1024).toFixed(1)     + ' KB';
    return                         (bytes / 1_048_576).toFixed(1) + ' MB';
}


// ─────────────────────────────────────────────────────────────────────────────
// 4. SHARE WITH USER MODAL
//
// Opened when the user clicks "Share with user" on an uploaded file.
// POSTs to php/share.php and shows success/error feedback inline.
// ─────────────────────────────────────────────────────────────────────────────

function initShareUserModal(csrf) {
    const shareModal = document.getElementById('shareUserModal');
    if (!shareModal) return;

    const closeBtn    = document.getElementById('shareUserModalClose');
    const submitBtn   = document.getElementById('shareUserSubmit');
    const usernameInput = document.getElementById('shareUserInput');
    const errorDiv    = document.getElementById('shareUserError');
    const successDiv  = document.getElementById('shareUserSuccess');

    if (closeBtn) closeBtn.onclick = () => { shareModal.style.display = 'none'; };
    shareModal.addEventListener('click', e => {
        if (e.target === shareModal) shareModal.style.display = 'none';
    });
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && shareModal.style.display === 'flex') {
                shareModal.style.display = 'none';
            }
        });

        if (!submitBtn) return;

        submitBtn.onclick = () => {
            errorDiv.style.display   = 'none';
            successDiv.style.display = 'none';

            const username = usernameInput.value.trim();
            if (!username) {
                errorDiv.textContent   = 'Enter a username.';
                errorDiv.style.display = 'block';
                return;
            }

            const fd = new FormData();
            fd.append('token',               shareModal.dataset.token);
            fd.append('share_with_username', username);
            fd.append('csrf_token',          csrf);

            submitBtn.disabled = true;

            fetch('php/share.php', { method: 'POST', body: fd })
            .then(r => { if (!r.ok) throw new Error('Server error'); return r.json(); })
            .then(data => {
                if (data.success) {
                    successDiv.textContent   = data.message ?? 'Shared!';
                    successDiv.style.display = 'block';
                    usernameInput.value      = '';
                } else {
                    errorDiv.textContent   = data.error ?? 'Error';
                    errorDiv.style.display = 'block';
                }
            })
            .catch(() => {
                errorDiv.textContent   = 'Network error.';
                errorDiv.style.display = 'block';
            })
            .finally(() => { submitBtn.disabled = false; });
        };

        // Allow pressing Enter in the username field to submit.
        usernameInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') submitBtn.click();
        });
}
