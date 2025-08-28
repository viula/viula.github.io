async function loadPosts() {
    try {
        const response = await fetch('../_posts/index.json');  // Percorso relativo
        const data = await response.json();
        displayPosts(data.posts);
    } catch (error) {
        console.error('Errore nel caricamento dei post:', error);
    }
}

function displayPosts(posts) {
    const postsContainer = document.getElementById('posts-container');
    
    posts.forEach(post => {
        const postElement = document.createElement('div');
        postElement.className = 'post';
        
        postElement.innerHTML = `
            <div class="post-title">${post.title}</div>
            <div class="post-meta">
                <span>📅 ${formatDate(post.date)}</span> · 
                <span>✍️ ${post.author}</span>
            </div>
            <div class="post-excerpt">
                ${post.excerpt}
                <p><a href="${post.url}">Leggi tutto →</a></p>
            </div>
        `;
        
        postsContainer.appendChild(postElement);
    });
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const options = { day: 'numeric', month: 'long', year: 'numeric' };
    return date.toLocaleDateString('it-IT', options);
}

document.addEventListener('DOMContentLoaded', loadPosts);