const child_process = require("child_process");

function runFromAgent(userInput) {
  child_process.exec(userInput);
}

function download(url) {
  return fetch(url);
}

