path = 'src/components/ToolRunnerPanel.tsx'
with open(path, encoding='utf-8') as f:
    content = f.read()

# Fix: wrap unsub in arrow function
old = "    return unsub"
new = "    return () => { unsub() }"

if old in content:
    # Make sure we're replacing the right instance
    count = content.count(old)
    if count == 1:
        content = content.replace(old, new)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print('Fixed ToolRunnerPanel useEffect return')
    else:
        print(f'Found {count} instances, need manual fix')
else:
    print('Pattern not found')
