"""Fix variable name bugs - function bodies reference old param names."""
with open('server.py', 'r', encoding='utf-8') as f:
    content = f.read()

changes = 0

old1 = '        result = await agent.parse(url)'
new1 = '        result = await agent.parse(req.url)'
if old1 in content:
    content = content.replace(old1, new1, 1)
    changes += 1
    print("1. url -> req.url [OK]")
else:
    print("1. SKIPPED")

old2 = '        results = agent.batch_check(targets)'
new2 = '        results = agent.batch_check(req.targets)'
if old2 in content:
    content = content.replace(old2, new2, 1)
    changes += 1
    print("2. targets -> req.targets [OK]")
else:
    print("2. SKIPPED")

with open('server.py', 'w', encoding='utf-8') as f:
    f.write(content)

print(f"Total: {changes}")
