import random

if __name__ == '__main__':
    max = 105
    min = 104
    num_of_file = 10
    num_min = 100
    num_max = 1000


    for id in range(num_of_file):
        count = random.randint(num_min,num_max)
        filename = str(id+1) + '.txt'
        f = open(filename, 'w')
        for i in range(count):
            num = random.randint(min,max)
            f.write(str(num) + ",")
        f.close()
