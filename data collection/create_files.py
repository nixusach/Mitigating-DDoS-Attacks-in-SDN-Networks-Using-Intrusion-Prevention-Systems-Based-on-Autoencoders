import os
from lorem_text import lorem

os.chdir("ftp/folder1")
for item in os.listdir():
    os.remove(item)

for i in range(1, 51):
    fichier = f"test{i}.txt"
    with open(fichier, "w") as file:
        file.write(lorem.paragraph())
        
os.chdir(".."); os.chdir("..")
os.system("ls Pictures | head -n $(($(ls Pictures | wc -l) / 2)) | xargs -I {} cp Pictures/{} ftp/folder1")

os.chdir("ftp/folder2")
for item in os.listdir():
    os.remove(item)

for i in range(1, 51):
    fichier = f"exemple{i}.txt"
    with open(fichier, "w") as file:
        file.write(lorem.paragraph())
      
os.chdir(".."); os.chdir("..")
os.system("ls Pictures | tail -n +$((($(ls Pictures | wc -l) / 2) + 1)) | xargs -I {} cp Pictures/{} ftp/folder2")

os.chdir("ftp/folder1")
print("\nFichiers en folder1:")
for item in os.listdir():
    print(item, end=' ')
 
os.chdir(".."); os.chdir("folder2")
print("\nFichiers en folder2:")
for item in os.listdir():
    print(item, end=' ')
print()



