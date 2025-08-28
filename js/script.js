async function displayPosts() {
    const postsContainer = document.getElementById('posts-container');
    
    for (const post of posts) {
        try {
            // Carica il contenuto Markdown
            const response = await fetch(post.markdownFile);
            const markdown = await response.text();
            
            // Converti Markdown in HTML
            const content = marked.parse(markdown);
            
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
                    <p><a href="#" onclick="showFullPost('${post.markdownFile}')">Leggi tutto →</a></p>
                </div>
            `;
            
            postsContainer.appendChild(postElement);
        } catch (error) {
            console.error(`Errore nel caricamento del post ${post.title}:`, error);
        }
    }
}

async function showFullPost(markdownFile) {
    try {
        const response = await fetch(markdownFile);
        const markdown = await response.text();
        const content = marked.parse(markdown);
        
        const postsContainer = document.getElementById('posts-container');
        postsContainer.innerHTML = `
            <div class="post full-post">
                ${content}
                <p><a href="#" onclick="displayPosts()">← Torna alla lista</a></p>
            </div>
        `;
    } catch (error) {
        console.error('Errore nel caricamento del post completo:', error);
    }
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const options = { day: 'numeric', month: 'long', year: 'numeric' };
    return date.toLocaleDateString('it-IT', options);
}

// Inizializza il display dei post quando la pagina è caricata
document.addEventListener('DOMContentLoaded', displayPosts);