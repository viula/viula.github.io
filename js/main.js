const user = "viula";
const repo = "viula.github.io";
const path = "posts";

fetch(`https://api.github.com/repos/${user}/${repo}/contents/${path}`)
  .then(response => response.json())
  .then(files => {
    const container = document.getElementById("posts");
    container.innerHTML = "";

    files
      .filter(f => f.name.endsWith(".md"))
      .sort((a, b) => b.name.localeCompare(a.name))
      .forEach(file => {
        fetch(file.download_url)
          .then(r => r.text())
          .then(md => {
            const article = document.createElement("article");
            article.className = "blog-post";
            article.innerHTML = marked.parse(md);
            container.appendChild(article);
          });
      });
  })
  .catch(err => console.error("GitHub API Error", err));
