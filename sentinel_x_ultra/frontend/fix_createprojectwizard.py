import re

path = 'src/components/CreateProjectWizard.tsx'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix: change the array iteration to avoid type narrowing issues
old = "          {(['location', 'type', 'summary'] as Step[]).map((s, i) =>"
new = "          {(['location', 'type', 'summary'] as const).map((s: Step, i) =>"

if old in content:
    content = content.replace(old, new)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Fixed CreateProjectWizard type comparison')
else:
    print('Pattern not found')
