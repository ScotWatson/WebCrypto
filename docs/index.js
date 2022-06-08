/*
(c) 2022 Scot Watson  All Rights Reserved
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

const promiseModuleCrypto = import("./Crypto.mjs").catch(function (error) {
  console.error(error);
  return error;
});

const promiseLoad = new Promise(function (resolve, reject) {
  window.addEventListener("load", function (evt) {
    resolve(evt);
  });
});

Promise.all( [ promiseModuleCrypto, promiseLoad ] ).then(function ( [ moduleCrypto, evtLoad ]) {
  document.body.style.backgroundColor = "black";
  document.body.style.color = "white";
  document.body.innerHTML = "Loaded";
  const inpNumRandomBytes = document.createElement("input");
  inpNumRandomBytes.type = "text";
  document.body.appendChild(inpNumRandomBytes);
  const btnRandomValues = document.createElement("button");
  btnRandomValues.innerHTML = "Get Random Values";
  btnRandomValues.addEventListener("click", function (evt) {
    const arrRandom = new Uint8Array(inpNumRandomBytes.value);
    moduleCrypto.getRandomValues(arrRandom);
  });
  document.body.appendChild(btnRandomValues);
});
