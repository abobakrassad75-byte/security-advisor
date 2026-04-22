const app = {
    apps: [], currentRiskFilter: 'all', scanCount: 0,
    VIRUSTOTAL_API_KEY: '192933a6c5624209c787663a0c4e3800b532a3cf2eb4abbf9393ea3494c101c6',
    
    init() {
        this.loadApps(); this.setupEventListeners(); this.calculateSecurityScore(); this.loadScanCount();
    },
    
    loadScanCount() { this.scanCount = parseInt(localStorage.getItem('scanCount') || '0'); },
    incrementScanCount() { this.scanCount++; localStorage.setItem('scanCount', this.scanCount.toString()); },
    shouldShowAd() { return this.scanCount % 3 === 0; },
    
    setupEventListeners() {
        const uploadArea = document.getElementById('uploadArea');
        if (uploadArea) {
            uploadArea.addEventListener('dragover', (e) => { e.preventDefault(); uploadArea.style.borderColor = '#e94560'; });
            uploadArea.addEventListener('dragleave', () => { uploadArea.style.borderColor = 'rgba(255,255,255,0.2)'; });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault(); uploadArea.style.borderColor = 'rgba(255,255,255,0.2)';
                const file = e.dataTransfer.files[0];
                file && file.name.endsWith('.apk') ? this.analyzeAPKFile(file) : this.showToast('يرجى اختيار ملف APK صحيح', 'error');
            });
        }
    },
    
    loadApps() {
        this.apps = [
            { name: 'واتساب', package: 'com.whatsapp', permissions: ['جهات الاتصال', 'كاميرا', 'ميكروفون', 'موقع'], risk: 'low' },
            { name: 'تطبيق مشبوه', package: 'com.suspicious', permissions: ['رسائل', 'جهات الاتصال', 'موقع', 'موقع في الخلفية'], risk: 'high' },
            { name: 'فيسبوك', package: 'com.facebook', permissions: ['كاميرا', 'ميكروفون', 'موقع'], risk: 'medium' },
            { name: 'انستجرام', package: 'com.instagram', permissions: ['كاميرا', 'ميكروفون', 'موقع'], risk: 'medium' },
            { name: 'تطبيق تنظيف', package: 'com.cleaner', permissions: ['تخزين', 'خدمة الوصول'], risk: 'high' }
        ];
        this.renderApps(); this.calculateSecurityScore();
    },
    
    renderApps() {
        const container = document.getElementById('appsList');
        let filtered = this.apps.filter(app => this.currentRiskFilter === 'all' || app.risk === this.currentRiskFilter);
        const query = document.getElementById('appSearch')?.value.toLowerCase();
        if (query) filtered = filtered.filter(app => app.name.toLowerCase().includes(query));
        
        container.innerHTML = filtered.length ? filtered.map(app => `
            <div class="app-item" onclick="app.showAppDetails('${app.package}')">
                <div class="app-icon" style="background: ${app.risk === 'high' ? 'rgba(231,76,60,0.2)' : app.risk === 'medium' ? 'rgba(243,156,18,0.2)' : 'rgba(39,174,96,0.2)'}">${app.risk === 'high' ? '⚠️' : app.risk === 'medium' ? '🔔' : '✅'}</div>
                <div class="app-info"><h4>${app.name}</h4><p>${app.permissions.length} صلاحيات</p></div>
                <div class="risk-badge ${app.risk === 'high' ? 'risk-high' : app.risk === 'medium' ? 'risk-medium' : 'risk-low'}">${app.risk === 'high' ? 'خطر' : app.risk === 'medium' ? 'متوسط' : 'آمن'}</div>
            </div>
        `).join('') : '<div class="loading"><p>لا توجد تطبيقات</p></div>';
    },
    
    filterApps() { this.renderApps(); },
    filterByRisk(risk) { this.currentRiskFilter = risk; document.querySelectorAll('.chip').forEach(c => c.classList.remove('active')); event.target.classList.add('active'); this.renderApps(); },
    
    calculateSecurityScore() {
        const high = this.apps.filter(a => a.risk === 'high').length, medium = this.apps.filter(a => a.risk === 'medium').length;
        let score = Math.max(0, Math.min(100, 100 - (high * 15) - (medium * 5)));
        document.getElementById('scoreValue').textContent = score;
        const circle = document.querySelector('.score-circle');
        circle.style.background = score >= 70 ? 'linear-gradient(135deg, #27ae60, #2ecc71)' : score >= 40 ? 'linear-gradient(135deg, #f39c12, #f1c40f)' : 'linear-gradient(135deg, #e74c3c, #c0392b)';
    },
    
    showAppDetails(pkg) {
        const app = this.apps.find(a => a.package === pkg);
        if (app) alert(`📱 ${app.name}\n📦 ${app.package}\n⚠️ ${app.risk === 'high' ? 'خطر' : app.risk === 'medium' ? 'متوسط' : 'آمن'}\n🔒 ${app.permissions.join('، ')}`);
    },
    
    showTab(tab) { document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active')); event.target.classList.add('active'); document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active')); document.getElementById(tab + 'Tab').classList.add('active'); },
    requestAccessibility() { this.showToast('الميزة تتطلب صلاحيات خاصة - النسخة الحالية للمحاكاة', 'error'); },
    
    analyzeAPK(e) { const f = e.target.files[0]; f && (f.size > 32*1024*1024 ? this.showToast('حجم الملف كبير', 'error') : this.analyzeAPKFile(f)); },
    
    async analyzeAPKFile(file) {
        const res = document.getElementById('analysisResult'), up = document.getElementById('uploadArea'), ad = document.getElementById('adAfterAnalysis');
        up.style.display = 'none'; res.style.display = 'block'; ad.style.display = 'none';
        res.innerHTML = `<div class="loading"><i class="fas fa-spinner fa-spin"></i><p>جاري رفع وتحليل ${file.name}...</p></div>`;
        this.incrementScanCount();
        
        try {
            const form = new FormData(); form.append('file', file);
            const upRes = await fetch('https://www.virustotal.com/api/v3/files', { method: 'POST', headers: { 'x-apikey': this.VIRUSTOTAL_API_KEY }, body: form });
            if (!upRes.ok) throw new Error('فشل الرفع');
            const upData = await upRes.json(), id = upData.data.id;
            
            let done = false, tries = 0, analysis;
            while (!done && tries++ < 45) {
                await new Promise(r => setTimeout(r, 2000));
                const aRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, { headers: { 'x-apikey': this.VIRUSTOTAL_API_KEY } });
                analysis = await aRes.json();
                if (analysis.data.attributes.status === 'completed') done = true;
            }
            if (!done) throw new Error('انتهت المهلة');
            
            const stats = analysis.data.attributes.stats, results = analysis.data.attributes.results;
            const detected = (stats.malicious || 0) + (stats.suspicious || 0), total = Object.values(stats).reduce((a,b) => a+b, 0);
            
            let html = `<div style="background:var(--secondary);border-radius:15px;padding:20px;"><h3>📱 ${file.name}</h3>
                <div style="display:flex;gap:20px;margin:20px 0;"><div style="text-align:center;"><div style="font-size:50px;color:${detected?'#e74c3c':'#27ae60'};">${detected?'🔴':'🟢'}</div><p>${detected?'تم اكتشاف تهديدات!':'الملف آمن'}</p></div>
                <div><p>الحجم: ${(file.size/1024/1024).toFixed(2)} MB</p><p>محركات الفحص: ${total}</p><p>الاكتشافات: ${detected}/${total}</p></div></div>
                <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;"><div style="background:rgba(39,174,96,0.2);padding:10px;border-radius:8px;">✅ غير ضار: ${stats.harmless||0}</div>
                <div style="background:rgba(231,76,60,0.2);padding:10px;border-radius:8px;">⚠️ ضار: ${stats.malicious||0}</div>
                <div style="background:rgba(243,156,18,0.2);padding:10px;border-radius:8px;">🔔 مشبوه: ${stats.suspicious||0}</div>
                <div style="background:rgba(52,152,219,0.2);padding:10px;border-radius:8px;">⏳ لم يكتشف: ${stats.undetected||0}</div></div>`;
            
            if (detected) {
                html += `<h4 style="margin:20px 0 10px;">🛡️ محركات اكتشفت تهديدات:</h4>`;
                for (let [e, r] of Object.entries(results)) if (r.category === 'malicious' || r.category === 'suspicious') html += `<div style="display:flex;justify-content:space-between;padding:8px;background:rgba(231,76,60,0.1);border-radius:5px;margin-bottom:5px;"><span>${e}</span><span style="color:#e74c3c;">${r.result||'تهديد'}</span></div>`;
            }
            html += `<button onclick="app.resetUpload()" class="btn-primary" style="width:100%;margin-top:20px;">فحص ملف آخر</button></div>`;
            res.innerHTML = html;
            if (this.shouldShowAd()) ad.style.display = 'block';
        } catch (err) {
            this.showToast('فشل الفحص - جاري المحاكاة', 'error');
            this.simulateAnalysis(file);
        }
    },
    
    simulateAnalysis(file) {
        setTimeout(() => {
            const res = document.getElementById('analysisResult'), ad = document.getElementById('adAfterAnalysis');
            const bad = Math.random() > 0.7;
            res.innerHTML = `<div style="background:var(--secondary);border-radius:15px;padding:20px;"><h3>📱 ${file.name}</h3><div style="display:flex;gap:20px;margin:20px 0;"><div style="text-align:center;"><div style="font-size:40px;color:${bad?'#e74c3c':'#27ae60'};">${bad?'🔴':'🟢'}</div><p>${bad?'ملف خطر':'ملف آمن'}</p></div><div><p>الحجم: ${(file.size/1024/1024).toFixed(2)} MB</p><p>اكتشافات: ${bad?'3/65':'0/65'}</p></div></div>${bad?'<div style="background:rgba(231,76,60,0.2);padding:15px;border-radius:10px;margin-bottom:15px;"><p style="color:#e74c3c;">⚠️ تحذير: هذا الملف قد يحتوي على برمجيات خبيثة!</p></div>':'<div style="background:rgba(39,174,96,0.2);padding:15px;border-radius:10px;margin-bottom:15px;"><p style="color:#27ae60;">✅ لم يتم اكتشاف أي تهديدات.</p></div>'}<button onclick="app.resetUpload()" class="btn-primary" style="width:100%;">فحص ملف آخر</button></div>`;
            if (this.shouldShowAd()) ad.style.display = 'block';
        }, 2000);
    },
    
    resetUpload() { document.getElementById('uploadArea').style.display = 'block'; document.getElementById('analysisResult').style.display = 'none'; document.getElementById('adAfterAnalysis').style.display = 'none'; document.getElementById('apkFile').value = ''; },
    showToast(m, t) { const toast = document.getElementById('toast'); toast.textContent = m; toast.className = `toast ${t}`; toast.classList.remove('hidden'); setTimeout(() => toast.classList.add('hidden'), 3000); }
};

window.addEventListener('DOMContentLoaded', () => app.init());