"""SEO boundaries for public and private application pages."""


def test_robots_advertises_sitemap_and_blocks_non_content_routes(client):
    response = client.get('/robots.txt')

    assert response.status_code == 200
    assert response.mimetype == 'text/plain'
    body = response.get_data(as_text=True)
    assert 'Sitemap: http://127.0.0.1:5000/sitemap.xml' in body
    assert 'Disallow: /api/' in body
    assert 'Disallow: /logout' in body


def test_sitemap_contains_only_public_canonical_pages(client):
    response = client.get('/sitemap.xml')

    assert response.status_code == 200
    assert response.mimetype == 'application/xml'
    body = response.get_data(as_text=True)
    assert '<loc>http://127.0.0.1:5000/</loc>' in body
    assert '<loc>http://127.0.0.1:5000/analyser</loc>' in body
    assert '/admin' not in body
    assert '/vault' not in body
    assert '/login' not in body


def test_public_pages_are_indexable_with_canonical_urls(client):
    landing = client.get('/').get_data(as_text=True)
    analyser = client.get('/analyser').get_data(as_text=True)

    assert 'content="index, follow, max-image-preview:large"' in landing
    assert 'rel="canonical" href="http://127.0.0.1:5000/"' in landing
    assert 'property="og:title"' in landing
    assert 'content="index, follow, max-image-preview:large"' in analyser
    assert 'rel="canonical" href="http://127.0.0.1:5000/analyser"' in analyser


def test_authentication_page_is_not_indexable(client):
    login = client.get('/login').get_data(as_text=True)

    assert 'content="noindex, nofollow"' in login
    assert 'rel="canonical"' not in login
