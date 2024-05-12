import numpy as np

def trilaterate(x1, x2, x3, y1, y2, y3, d1, d2, d3):
    A1 = 2 * (x2 - x1)
    A2 = 2 * (x3 - x1)
    A3 = 2 * (x3 - x2)
    B1 = 2 * (y2 - y1)
    B2 = 2 * (y3 - y1)
    B3 = 2 * (y3 - y2)
    C1 = d1**2 - d2**2 + x2**2 - x1**2 + y2**2 - y1**2
    C2 = d1**2 - d3**2 + x3**2 - x1**2 + y3**2 - y1**2
    C3 = d2**2 - d3**2 + x3**2 - x2**2 + y3**2 - y2**2

    # Define the matrices
    matrix1 = np.array([[A1**2 + A2**2 + A3**2, A1*B1 + A2*B2 + A3*B3],
                        [A1*B1 + A2*B2 + A3*B3, B1**2 + B2**2 + B3**2]])

    matrix2 = np.array([[A1*C1 + A2*C2 + A3*C3], 
                        [B1*C1 + B2*C2 + B3*C3]])

    inverse_matrix = np.linalg.inv(matrix1)

    # Perform matrix multiplication
    result_2d_array = np.dot(inverse_matrix, matrix2)
    result = {'x': result_2d_array[0][0], 'y': result_2d_array[1][0]}

    print("Result of matrix multiplication:")
    print(result)
    return result

# example: should return 55,45
# trilaterate(1, 400, -430, 1, 750, -435, 21, 35, 25) 
"""
Result of matrix multiplication:
{'x': 55.08888888888889, 'y': 45.22222222222222}
"""
