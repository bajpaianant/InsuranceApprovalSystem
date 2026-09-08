document.querySelectorAll('button[value="deny"]').forEach((btn) => {
  btn.addEventListener("click", (event) => {
    if (!window.confirm("Deny this claim and record the decision in the audit log?")) {
      event.preventDefault();
    }
  });
});
