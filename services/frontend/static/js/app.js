const API_BASE = '/api/v1';

// Collection metadata: defines display columns, ID field, and editable fields
const COLLECTIONS = {
    'personnel': {
        label: 'Personnel',
        idField: 'employee_id',
        columns: ['employee_id', 'first_name', 'last_name', 'role', 'department', 'clearance_level', 'classification_level', 'status'],
        fields: [
            { key: 'employee_id', label: 'Employee ID', type: 'text' },
            { key: 'first_name', label: 'First Name', type: 'text' },
            { key: 'last_name', label: 'Last Name', type: 'text' },
            { key: 'role', label: 'Role', type: 'select', options: ['operator', 'maintenance_technician', 'radiation_protection_officer', 'security_officer', 'plant_manager', 'inspector'] },
            { key: 'department', label: 'Department', type: 'text' },
            { key: 'clearance_level', label: 'Clearance Level', type: 'select', options: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'] },
            { key: 'classification_level', label: 'Classification', type: 'select', options: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'] },
            { key: 'status', label: 'Status', type: 'select', options: ['active', 'inactive', 'suspended'] },
            { key: 'badge_id', label: 'Badge ID', type: 'text' },
        ]
    },
    'zones': {
        label: 'Zones',
        idField: 'zone_id',
        columns: ['zone_id', 'name', 'type', 'classification_level', 'required_clearance', 'radiation_zone', 'status'],
        fields: [
            { key: 'zone_id', label: 'Zone ID', type: 'text' },
            { key: 'name', label: 'Name', type: 'text' },
            { key: 'code', label: 'Code', type: 'text' },
            { key: 'type', label: 'Type', type: 'select', options: ['public', 'controlled', 'restricted', 'exclusion'] },
            { key: 'classification_level', label: 'Classification', type: 'select', options: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'] },
            { key: 'required_clearance', label: 'Required Clearance', type: 'select', options: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'] },
            { key: 'radiation_zone', label: 'Radiation Zone', type: 'select', options: ['true', 'false'] },
            { key: 'max_occupancy', label: 'Max Occupancy', type: 'number' },
            { key: 'status', label: 'Status', type: 'select', options: ['active', 'inactive', 'maintenance'] },
        ]
    },
    'badges': {
        label: 'Access Badges',
        idField: 'badge_id',
        columns: ['badge_id', 'employee_id', 'type', 'classification_level', 'status', 'expiry_date'],
        fields: [
            { key: 'badge_id', label: 'Badge ID', type: 'text' },
            { key: 'employee_id', label: 'Employee ID', type: 'text' },
            { key: 'type', label: 'Type', type: 'select', options: ['permanent', 'temporary', 'visitor', 'contractor'] },
            { key: 'classification_level', label: 'Classification', type: 'select', options: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'] },
            { key: 'status', label: 'Status', type: 'select', options: ['active', 'inactive', 'revoked', 'expired'] },
        ]
    },
    'reactor-parameters': {
        label: 'Reactor Parameters',
        idField: 'reactor_id',
        columns: ['reactor_id', 'timestamp', 'thermal_power_mw', 'electrical_power_mw', 'reactor_status', 'classification_level'],
        fields: [
            { key: 'reactor_id', label: 'Reactor ID', type: 'text' },
            { key: 'thermal_power_mw', label: 'Thermal Power (MW)', type: 'number' },
            { key: 'electrical_power_mw', label: 'Electrical Power (MW)', type: 'number' },
            { key: 'neutron_flux', label: 'Neutron Flux', type: 'number' },
            { key: 'reactor_status', label: 'Status', type: 'select', options: ['shutdown', 'startup', 'power_operation', 'hot_standby', 'emergency_shutdown'] },
            { key: 'classification_level', label: 'Classification', type: 'select', options: ['SECRET', 'TOP_SECRET'] },
        ]
    },
    'maintenance-orders': {
        label: 'Maintenance Orders',
        idField: 'order_id',
        columns: ['order_id', 'title', 'type', 'priority', 'status', 'safety_classification', 'zone_id'],
        fields: [
            { key: 'order_id', label: 'Order ID', type: 'text' },
            { key: 'title', label: 'Title', type: 'text' },
            { key: 'type', label: 'Type', type: 'select', options: ['preventive', 'corrective', 'predictive'] },
            { key: 'priority', label: 'Priority', type: 'select', options: ['low', 'medium', 'high', 'critical'] },
            { key: 'system', label: 'System', type: 'text' },
            { key: 'equipment_id', label: 'Equipment ID', type: 'text' },
            { key: 'zone_id', label: 'Zone ID', type: 'text' },
            { key: 'description', label: 'Description', type: 'text' },
            { key: 'safety_classification', label: 'Safety Class', type: 'select', options: ['safety_related', 'non_safety', 'augmented_quality'] },
            { key: 'status', label: 'Status', type: 'select', options: ['created', 'approved', 'scheduled', 'in_progress', 'completed', 'cancelled'] },
        ]
    },
    'documents': {
        label: 'Documents',
        idField: 'document_id',
        columns: ['document_id', 'title', 'type', 'category', 'classification_level', 'status'],
        fields: [
            { key: 'document_id', label: 'Document ID', type: 'text' },
            { key: 'title', label: 'Title', type: 'text' },
            { key: 'type', label: 'Type', type: 'select', options: ['procedure', 'manual', 'drawing', 'report', 'analysis'] },
            { key: 'category', label: 'Category', type: 'select', options: ['operational', 'emergency', 'maintenance', 'safety', 'administrative'] },
            { key: 'classification_level', label: 'Classification', type: 'select', options: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'] },
            { key: 'status', label: 'Status', type: 'select', options: ['draft', 'under_review', 'approved', 'superseded', 'archived'] },
            { key: 'file_reference', label: 'File Reference', type: 'text' },
        ]
    },
    'nuclear-materials': {
        label: 'Nuclear Materials',
        idField: 'material_id',
        columns: ['material_id', 'type', 'description', 'classification_level', 'status', 'serial_number'],
        fields: [
            { key: 'material_id', label: 'Material ID', type: 'text' },
            { key: 'type', label: 'Type', type: 'select', options: ['fuel_assembly', 'spent_fuel', 'waste', 'source'] },
            { key: 'description', label: 'Description', type: 'text' },
            { key: 'classification_level', label: 'Classification', type: 'select', options: ['SECRET', 'TOP_SECRET'] },
            { key: 'status', label: 'Status', type: 'select', options: ['in_storage', 'in_reactor', 'spent_pool', 'dry_cask', 'transferred'] },
            { key: 'serial_number', label: 'Serial Number', type: 'text' },
            { key: 'mass_kg', label: 'Mass (kg)', type: 'number' },
            { key: 'supplier', label: 'Supplier', type: 'text' },
        ]
    }
};

let currentCollection = 'personnel';
let currentData = [];

// DOM references
const pageTitle = document.getElementById('page-title');
const tableContainer = document.getElementById('table-container');
const loading = document.getElementById('loading');
const errorMsg = document.getElementById('error-msg');
const modalOverlay = document.getElementById('modal-overlay');
const modalTitle = document.getElementById('modal-title');
const modalForm = document.getElementById('modal-form');
const detailOverlay = document.getElementById('detail-overlay');
const detailTitle = document.getElementById('detail-title');
const detailContent = document.getElementById('detail-content');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupModalHandlers();
    loadCollection(currentCollection);
});

function setupNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            currentCollection = link.dataset.collection;
            pageTitle.textContent = COLLECTIONS[currentCollection].label;
            loadCollection(currentCollection);
        });
    });

    document.getElementById('btn-refresh').addEventListener('click', () => {
        loadCollection(currentCollection);
    });

    document.getElementById('btn-create').addEventListener('click', () => {
        openCreateModal();
    });
}

function setupModalHandlers() {
    document.getElementById('modal-close').addEventListener('click', closeModal);
    document.getElementById('modal-cancel').addEventListener('click', closeModal);
    document.getElementById('modal-save').addEventListener('click', saveRecord);
    document.getElementById('detail-close').addEventListener('click', closeDetail);

    modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) closeModal();
    });
    detailOverlay.addEventListener('click', (e) => {
        if (e.target === detailOverlay) closeDetail();
    });
}

// API calls
async function apiCall(method, path, body) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(`${API_BASE}${path}`, opts);

    if (res.status === 204) return null;

    if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
    }

    return res.json();
}

async function loadCollection(name) {
    showLoading(true);
    hideError();
    try {
        const data = await apiCall('GET', `/${name}`);
        currentData = data || [];
        renderTable(name, currentData);
    } catch (err) {
        showError(`Failed to load ${name}: ${err.message}`);
        tableContainer.innerHTML = '';
    } finally {
        showLoading(false);
    }
}

// Rendering
function renderTable(collectionName, data) {
    const meta = COLLECTIONS[collectionName];
    if (!data || data.length === 0) {
        tableContainer.innerHTML = '<p style="padding:2rem;color:var(--text-muted);text-align:center;">No records found.</p>';
        return;
    }

    const thead = meta.columns.map(col => `<th>${formatHeader(col)}</th>`).join('') + '<th>Actions</th>';

    const tbody = data.map((row, idx) => {
        const cells = meta.columns.map(col => {
            const val = getNestedValue(row, col);
            if (col === 'classification_level') return `<td>${classificationBadge(val)}</td>`;
            if (col === 'radiation_zone') return `<td>${val ? 'Yes' : 'No'}</td>`;
            return `<td title="${escapeHtml(String(val ?? ''))}">${escapeHtml(formatValue(val))}</td>`;
        }).join('');

        return `<tr>
            ${cells}
            <td class="actions-cell">
                <button class="btn btn-secondary btn-sm" onclick="viewRecord(${idx})">View</button>
                <button class="btn btn-primary btn-sm" onclick="editRecord(${idx})">Edit</button>
                <button class="btn btn-danger btn-sm" onclick="deleteRecord(${idx})">Del</button>
            </td>
        </tr>`;
    }).join('');

    tableContainer.innerHTML = `<table><thead><tr>${thead}</tr></thead><tbody>${tbody}</tbody></table>`;
}

function formatHeader(key) {
    return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatValue(val) {
    if (val === null || val === undefined) return '-';
    if (typeof val === 'object') {
        if (val instanceof Array) return `[${val.length} items]`;
        return '{...}';
    }
    const str = String(val);
    // Truncate ISO date strings to date part
    if (/^\d{4}-\d{2}-\d{2}T/.test(str)) return str.substring(0, 10);
    return str;
}

function getNestedValue(obj, key) {
    return key.split('.').reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);
}

function classificationBadge(level) {
    if (!level) return '-';
    const cls = level.toLowerCase().replace(/_/g, '-');
    return `<span class="badge badge-${cls}">${level}</span>`;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// CRUD operations
function viewRecord(idx) {
    const record = currentData[idx];
    const meta = COLLECTIONS[currentCollection];
    detailTitle.textContent = `${meta.label} - ${record[meta.idField] || 'Detail'}`;
    detailContent.innerHTML = `<pre>${JSON.stringify(record, null, 2)}</pre>`;
    detailOverlay.style.display = 'flex';
}

function openCreateModal() {
    const meta = COLLECTIONS[currentCollection];
    modalTitle.textContent = `New ${meta.label}`;
    modalForm.innerHTML = '';
    modalForm.dataset.mode = 'create';
    modalForm.dataset.editIdx = '';

    meta.fields.forEach(f => {
        modalForm.appendChild(createFormGroup(f, ''));
    });

    modalOverlay.style.display = 'flex';
}

function editRecord(idx) {
    const record = currentData[idx];
    const meta = COLLECTIONS[currentCollection];
    modalTitle.textContent = `Edit ${meta.label}`;
    modalForm.innerHTML = '';
    modalForm.dataset.mode = 'edit';
    modalForm.dataset.editIdx = idx;

    meta.fields.forEach(f => {
        const val = record[f.key] ?? '';
        const group = createFormGroup(f, val);
        // Disable ID field on edit
        if (f.key === meta.idField) {
            group.querySelector('input, select').disabled = true;
        }
        modalForm.appendChild(group);
    });

    modalOverlay.style.display = 'flex';
}

function createFormGroup(field, value) {
    const div = document.createElement('div');
    div.className = 'form-group';

    const label = document.createElement('label');
    label.textContent = field.label;
    div.appendChild(label);

    let input;
    if (field.type === 'select') {
        input = document.createElement('select');
        input.name = field.key;
        const emptyOpt = document.createElement('option');
        emptyOpt.value = '';
        emptyOpt.textContent = '-- Select --';
        input.appendChild(emptyOpt);
        field.options.forEach(opt => {
            const o = document.createElement('option');
            o.value = opt;
            o.textContent = opt;
            if (String(value) === opt) o.selected = true;
            input.appendChild(o);
        });
    } else {
        input = document.createElement('input');
        input.type = field.type === 'number' ? 'number' : 'text';
        input.name = field.key;
        input.value = value;
        if (field.type === 'number') input.step = 'any';
    }

    div.appendChild(input);
    return div;
}

async function saveRecord() {
    const meta = COLLECTIONS[currentCollection];
    const mode = modalForm.dataset.mode;
    const formData = {};

    meta.fields.forEach(f => {
        const el = modalForm.querySelector(`[name="${f.key}"]`);
        if (!el) return;
        let val = el.value;
        if (f.type === 'number' && val !== '') val = parseFloat(val);
        if (f.key === 'radiation_zone') val = val === 'true';
        if (val !== '' && val !== null) formData[f.key] = val;
    });

    try {
        if (mode === 'create') {
            await apiCall('POST', `/${currentCollection}`, formData);
        } else {
            const id = currentData[modalForm.dataset.editIdx][meta.idField];
            await apiCall('PUT', `/${currentCollection}/${id}`, formData);
        }
        closeModal();
        loadCollection(currentCollection);
    } catch (err) {
        showError(`Save failed: ${err.message}`);
    }
}

async function deleteRecord(idx) {
    const meta = COLLECTIONS[currentCollection];
    const id = currentData[idx][meta.idField];
    if (!confirm(`Delete ${meta.label} "${id}"?`)) return;

    try {
        await apiCall('DELETE', `/${currentCollection}/${id}`);
        loadCollection(currentCollection);
    } catch (err) {
        showError(`Delete failed: ${err.message}`);
    }
}

// UI helpers
function showLoading(show) {
    loading.style.display = show ? 'block' : 'none';
}

function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.style.display = 'block';
}

function hideError() {
    errorMsg.style.display = 'none';
}

function closeModal() {
    modalOverlay.style.display = 'none';
    modalForm.innerHTML = '';
}

function closeDetail() {
    detailOverlay.style.display = 'none';
}
