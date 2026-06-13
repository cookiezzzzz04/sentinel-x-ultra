import os

png = 'photo/Schermafbeelding 2026-06-13 174609.png'
if os.path.exists(png):
    os.remove(png)
    print(f'Deleted {png}')
else:
    print(f'{png} not found')
