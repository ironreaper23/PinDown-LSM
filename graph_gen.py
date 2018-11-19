import matplotlib.pyplot as plt 
  
# read points without PinUP 
x1 = [10,50,100,250,500,1000] 
y1 = [89192,86994,83629,85092,82181,87469] 
# plotting the read points without PinUP points  
plt.plot(x1, y1, label = "Without PinDOWN") 

# read points with PinUP
x2 = [10,50,100,250,500,1000] 
y2 = [89643,73660,80355,66682,71742,68463] 
# plotting the read points with PinUP points
plt.plot(x2, y2, label = "With PinDOWN") 
  
# naming the x axis 
plt.xlabel('File Size(Mb)') 
# naming the y axis 
plt.ylabel('Read rate (K/sec)') 
# giving a title to my graph 
plt.title('Read variations with and without PinDOWN') 
  
# show a legend on the plot 
plt.legend() 
  
# function to show the plot 
plt.show()