const search=document.querySelector('#search');
if(search){
    search.addEventListener("input",()=>{
        let matches=0
        document.querySelectorAll('.resource-card').forEach(card=>{
            const visisble=card.dataset.search.includes(search.value.trim());
            card.hidden = !visisble;
            if (visisble) matches++;
            })
            document.querySelector('#no-results').hidden = matches > 0;  
    })
}