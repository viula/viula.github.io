const posts = [
    {
        url: "/2025/08/28/il-mio-primo-post.html",
        title: "Il mio primo post",
        date: "2025-08-28",
        author: "Andrea",
        excerpt: "Benvenuti nel mio nuovo sito su GitHub Pages 🎉"
    }
    // Aggiungi altri post qui
];

function displayPosts() {
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

// Inizializza il display dei post quando la pagina è caricata
document.addEventListener('DOMContentLoaded', displayPosts);