/**
 * app.js — All client-side JavaScript for the application.
 *
 * This file handles three independent features:
 *   1. The password modal (pop-up dialog used on the dashboard and download page)
 *   2. Dashboard action buttons (Share / Download trigger the modal)
 *   3. File upload preview (shows the selected file before submitting)
 *
 * We wait for DOMContentLoaded before running, which guarantees that all HTML
 * elements exist before we try to find them.
 */
document.addEventListener('DOMContentLoaded', () => {

    // The CSRF token is embedded in a <meta> tag by PHP's csrfMetaTag() function.
    // We must include it in every fetch() POST so the server can verify the request
    // didn't come from a malicious third-party website (CSRF protection).
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content ?? '';

    const modal = document.getElementById('passwordModal');

    // Only initialise features whose HTML elements exist on this page.
    if (modal) initModal(modal, csrf);
    initDashboardButtons(modal);
    initFilePreview();
});


// ─────────────────────────────────────────────────────────────────────────────
// 1. PASSWORD MODAL
//
// The modal reads its configuration from data-* attributes on the #passwordModal div.
// These attributes are set either by PHP (render_modal) or by the dashboard buttons below.
//
//   data-token       — the file's share token
//   data-action      — 'download' or 'share'
//   data-verify-url  — the PHP endpoint to POST the password to
//   data-success-url — where to redirect after success; {token} is replaced at runtime
// ─────────────────────────────────────────────────────────────────────────────

function initModal(modal, csrf) {
    const closeBtn  = document.getElementById('modalClose');
    const form      = document.getElementById('passwordForm');
    const errorDiv  = document.getElementById('modalError');
    const passInput = document.getElementById('modalPassword');

    // Three ways to close the modal without submitting the form.
    if (closeBtn) closeBtn.onclick = () => closeModal(modal);
    modal.addEventListener('click', e => {
        // Only close if the user clicked the dark overlay, not the white card inside.
        if (e.target === modal) closeModal(modal);
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && modal.style.display === 'flex') closeModal(modal);
    });

    if (!form) return;

    form.onsubmit = e => {
        e.preventDefault();  // Stop the form from doing a normal page-reload submit.
        errorDiv.style.display = 'none';

        const action = modal.dataset.action ?? 'download';

        // Build the POST body. FormData automatically handles encoding.
        const fd = new FormData();
        fd.append('token',      modal.dataset.token);
        fd.append('password',   passInput.value);
        fd.append('action',     action);
        fd.append('csrf_token', csrf);

        // Send the password to verify.php and wait for a JSON response.
        fetch(modal.dataset.verifyUrl, { method: 'POST', body: fd })
            .then(response => {
                // Treat any non-2xx HTTP status as a failure.
                if (!response.ok) throw new Error('Server error');
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    if (action === 'share') {
                        // Build the shareable download URL and copy it to the clipboard.
                        const base = window.location.origin
                            + window.location.pathname.replace(/\/(index\.php)?$/, '');
                        const url  = `${base}/php/download.php?token=${encodeURIComponent(modal.dataset.token)}`;

                        navigator.clipboard.writeText(url)
                            .then(()  => alert('Copied!'))
                            .catch(() => alert('Link:\n' + url));  // Fallback if clipboard is denied.

                        closeModal(modal);
                    } else {
                        // Replace the {token} placeholder in the success URL and redirect.
                        window.location.href = modal.dataset.successUrl
                            .replace('{token}', encodeURIComponent(modal.dataset.token));
                    }
                } else {
                    // Show the server's error message inside the modal.
                    errorDiv.textContent   = data.error ?? 'Error';
                    errorDiv.style.display = 'block';
                    passInput.value        = '';  // Clear the password field so they can retry.
                    passInput.focus();
                }
            })
            .catch(() => {
                errorDiv.textContent   = 'Network error.';
                errorDiv.style.display = 'block';
            });
    };
}

/** Opens the modal by making it visible. */
function openModal(modal) {
    modal.style.display = 'flex';
}

/** Closes the modal by hiding it. */
function closeModal(modal) {
    modal.style.display = 'none';
}


// ─────────────────────────────────────────────────────────────────────────────
// 2. DASHBOARD ACTION BUTTONS
//
// Each Share and Download button in the file table has data-* attributes:
//   data-token    — the file's share token
//   data-filename — the human-readable filename to show inside the modal
//   data-action   — 'share' or 'download'
//
// Clicking a button loads these values into the modal, then opens it.
// ─────────────────────────────────────────────────────────────────────────────

function initDashboardButtons(modal) {
    if (!modal) return;  // These buttons only exist on the dashboard page.

    document.querySelectorAll('.action-btn').forEach(button => {
        button.onclick = function () {
            // Load this button's file info into the modal.
            modal.dataset.token  = this.dataset.token;
            modal.dataset.action = this.dataset.action;

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
//
// When the user selects a file, show a small preview below the file input:
//   - For images: a thumbnail generated from the local file (no upload needed).
//   - For other files: a 📄 icon.
// The × button resets the input and hides the preview.
// ─────────────────────────────────────────────────────────────────────────────

function initFilePreview() {
    const fileInput    = document.getElementById('fileToUpload');
    if (!fileInput) return;  // Only exists on the dashboard page.

    const preview      = document.getElementById('filePreview');
    const previewThumb = document.getElementById('filePreviewThumb');
    const previewName  = document.getElementById('filePreviewName');
    const previewSize  = document.getElementById('filePreviewSize');
    const removeBtn    = document.getElementById('filePreviewRemove');

    fileInput.onchange = () => {
        const file = fileInput.files[0];

        if (!file) {
            preview.style.display = 'none';
            return;
        }

        previewName.textContent = file.name;
        previewSize.textContent = formatFileSize(file.size);

        if (file.type.startsWith('image/')) {
            // URL.createObjectURL() creates a temporary local URL for the file —
            // the image is shown in the browser without uploading it to the server.
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
        fileInput.value       = '';  // Clears the file selection.
        preview.style.display = 'none';
    };
}

/**
 * Converts a number of bytes into a readable string like "1.4 MB".
 * Used to show the file size in the upload preview.
 */
function formatFileSize(bytes) {
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1_048_576)  return (bytes / 1024).toFixed(1)     + ' KB';
    return                         (bytes / 1_048_576).toFixed(1) + ' MB';
}
