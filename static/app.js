(function () {
  'use strict';
  window.bvEscapeHTML = function (value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (character) {
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character];
    });
  };
  var nativeFetch = window.fetch;
  window.fetch = function (input, init) {
    init = init || {};
    var method = String(init.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      var headers = new Headers(init.headers || {});
      var csrf = document.querySelector('meta[name="csrf-token"]');
      if (csrf) headers.set('X-CSRF-Token', csrf.content);
      init.headers = headers;
    }
    return nativeFetch.call(this, input, init);
  };
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('form[method="POST"], form[method="post"]').forEach(function (form) {
      if (form.querySelector('input[name="csrf_token"]')) return;
      var input = document.createElement('input');
      input.type = 'hidden'; input.name = 'csrf_token';
      input.value = document.querySelector('meta[name="csrf-token"]').content;
      form.appendChild(input);
    });
  });
})();
