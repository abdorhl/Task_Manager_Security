async function loadDashboardSummary() {
    try {
        const response = await fetch('/tasks', {
            headers: {
                'CSRF-Token': localStorage.getItem('csrfToken')
            }
        });
        
        if (!response.ok) throw new Error('Failed to load tasks');
        
        const tasks = await response.json();
        document.getElementById('taskCount').textContent = tasks.length;
    } catch (error) {
        alert('Error loading dashboard: ' + error.message);
    }
}

document.addEventListener('DOMContentLoaded', loadDashboardSummary);