let cache_name = 'pwaPassbox'
let filesToCache = [
    './template/base.html',
    'index.js',
    'style.css',
    'style_home.css'
];

self.addEventListener('install', function (e) {
    e.waitUntil(
        caches.open(cache_name).then(function (cache) {
            return cache.addAll(filesToCache);
        })
    );
});

self.addEventListener('fetch', function (e) {
    e.respondWith(
        caches.match(e.request).then(function (response) {
            return response || fetch(e.request);
        })
    );
});