document.addEventListener('DOMContentLoaded', () => {
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const modal = document.getElementById('passwordModal');
    if (modal) initModal(modal, csrf);
    initDashboardActions(modal);
    initFilePreview();
});

function initModal(modal, csrf) {
    const closeBtn = document.getElementById('modalClose');
    const form = document.getElementById('passwordForm');
    const errorDiv = document.getElementById('modalError');
    const passInput = document.getElementById('modalPassword');

    if (closeBtn) closeBtn.onclick = () => modal.style.display = 'none';
    modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && modal.style.display === 'flex') modal.style.display = 'none'; });

    if (form) form.onsubmit = (e) => {
        e.preventDefault(); errorDiv.style.display = 'none';
        const action = modal.dataset.action || 'download';
        const fd = new FormData();
        fd.append('token', modal.dataset.token); fd.append('password', passInput.value); fd.append('action', action); fd.append('csrf_token', csrf);

        fetch(modal.dataset.verifyUrl, { method: 'POST', body: fd })
            .then(r => { if (!r.ok) throw new Error(); return r.json(); })
            .then(data => {
                if (data.success) {
                    if (action === 'share') {
                        const url = `${window.location.origin}${window.location.pathname.replace(/\/(index\.php)?$/, '')}/php/download.php?token=${encodeURIComponent(modal.dataset.token)}`;
                        navigator.clipboard.writeText(url).then(() => alert('Copied!')).catch(() => alert('Link:\n' + url));
                        modal.style.display = 'none';
                    } else window.location.href = modal.dataset.successUrl.replace('{token}', encodeURIComponent(modal.dataset.token));
                } else { errorDiv.textContent = data.error || 'Error'; errorDiv.style.display = 'block'; passInput.value = ''; passInput.focus(); }
            }).catch(() => { errorDiv.textContent = 'Network error.'; errorDiv.style.display = 'block'; });
    };
}

function initDashboardActions(modal) {
    document.querySelectorAll('.action-btn').forEach(btn => btn.onclick = function() {
        if (!modal) return;
        modal.dataset.token = this.dataset.token; modal.dataset.action = this.dataset.action;
        document.getElementById('modalFilename').textContent = this.dataset.filename;
        document.getElementById('modalPassword').value = ''; document.getElementById('modalError').style.display = 'none';
        modal.style.display = 'flex'; document.getElementById('modalPassword').focus();
    });
}

function initFilePreview() {
    const input = document.getElementById('fileToUpload'); if (!input) return;
    const preview = document.getElementById('filePreview'), thumb = document.getElementById('filePreviewThumb'), name = document.getElementById('filePreviewName'), size = document.getElementById('filePreviewSize'), remove = document.getElementById('filePreviewRemove');
    const fmt = b => b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB';

    input.onchange = () => {
        const f = input.files[0]; if (!f) { preview.style.display = 'none'; return; }
        name.textContent = f.name; size.textContent = fmt(f.size);
        if (f.type.startsWith('image/')) { thumb.innerHTML = ''; const img = document.createElement('img'); img.src = URL.createObjectURL(f); thumb.appendChild(img); } 
        else thumb.innerHTML = '📄';
        preview.style.display = 'flex';
    };
    remove.onclick = () => { input.value = ''; preview.style.display = 'none'; };
}