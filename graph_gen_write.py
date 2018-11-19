import matplotlib.pyplot as plt 
  
# write points without PinUP 
x1 = [10,50,100,250,500,750,1000] 
y1 = [79937,59457,77360,12143,13490,17621,29625] 
# plotting the write points without PinUP points  
plt.plot(x1, y1, label = "Without PinDOWN") 

# write points with PinUP
x2 = [10,50,100,250,500,750,1000] 
y2 = [76582,74979,78952,76576,57758,63866,66908] 
# plotting the write points with PinUP points
plt.plot(x2, y2, label = "With PinDOWN") 
  
# naming the x axis 
plt.xlabel('File Size(Mb)') 
# naming the y axis 
plt.ylabel('Write rate (K/sec)') 
# giving a title to my graph 
plt.title('Write variations with and without PinDOWN') 
  
# show a legend on the plot 
plt.legend() 
  
# function to show the plot 
plt.show()