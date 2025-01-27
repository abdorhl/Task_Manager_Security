// Global CSRF token
let csrfToken = null;

// Fetch CSRF token when page loads
async function fetchCsrfToken() {
    try {
        const response = await fetch('/csrf-token');
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to fetch security token');
        }
        const data = await response.json();
        csrfToken = data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        alert('Error loading page security. Please refresh and try again.');
    }
}

async function loadTasks() {
    try {
        if (!csrfToken) {
            await fetchCsrfToken();
        }

        const response = await fetch('/tasks', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'CSRF-Token': csrfToken
            },
            credentials: 'same-origin'
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to load tasks');
        }
        
        const tasks = await response.json();
        const container = document.getElementById('taskContainer');
        container.innerHTML = '';

        if (tasks.length === 0) {
            container.innerHTML = '<p class="no-tasks">No tasks yet. Add your first task above!</p>';
            return;
        }

        tasks.forEach(task => {
            const taskElement = document.createElement('div');
            taskElement.className = 'task-card';
            taskElement.innerHTML = `
                <h3>${task.title}</h3>
                ${task.description ? `<p>${task.description}</p>` : ''}
                <div class="task-footer">
                    <button onclick="deleteTask('${task.id}')" class="delete-btn">Delete</button>
                </div>
            `;
            container.appendChild(taskElement);
        });

        // Update task count
        const taskCount = document.getElementById('taskCount');
        if (taskCount) {
            taskCount.textContent = tasks.length;
        }
    } catch (error) {
        console.error('Error loading tasks:', error);
        alert('Error loading tasks: ' + error.message);
    }
}

async function deleteTask(taskId) {
    try {
        if (!csrfToken) {
            await fetchCsrfToken();
        }

        console.log('Deleting task with ID:', taskId);

        const response = await fetch(`/tasks/${taskId}`, {
            method: 'DELETE',
            headers: {
                'Accept': 'application/json',
                'CSRF-Token': csrfToken
            },
            credentials: 'same-origin'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to delete task');
        }
        
        await loadTasks();
    } catch (error) {
        console.error('Error deleting task:', error);
        alert('Error deleting task: ' + error.message);
    }
}

document.getElementById('addTaskForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    if (!csrfToken) {
        try {
            await fetchCsrfToken();
        } catch (error) {
            alert('Error: Could not secure the form. Please refresh the page.');
            return;
        }
    }

    const title = document.getElementById('title').value.trim();
    const description = document.getElementById('description').value.trim();

    if (!title || !description) {
        alert('Please fill in both title and description');
        return;
    }

    try {
        const response = await fetch('/tasks', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'CSRF-Token': csrfToken
            },
            credentials: 'same-origin',
            body: JSON.stringify({ title, description })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to add task');
        }

        document.getElementById('addTaskForm').reset();
        await loadTasks();
    } catch (error) {
        console.error('Error adding task:', error);
        alert('Error adding task: ' + error.message);
    }
});

// Initialize dashboard
async function initializeDashboard() {
    try {
        await fetchCsrfToken();
        await loadTasks();
    } catch (error) {
        console.error('Failed to initialize dashboard:', error);
        alert('Error loading dashboard. Please refresh the page.');
    }
}

// Start initialization when page loads
document.addEventListener('DOMContentLoaded', initializeDashboard);