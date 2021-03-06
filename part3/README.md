# CS-523 Project 2 Part 3: Cell Fingerprinting via Network Traffic Analysis

This is the README.md file for the third part of the second project of the Advanced Topics in Privacy Enhancing Technologies class in Spring 2021.

## Authors

[Furkan Karakaş](mailto:furkan.karakas@epfl.ch)

[Pascal Andreas Schärli](mailto:pascal.scharli@epfl.ch)

## Data collection

In order to collect data, we used the script `collect_data.py` which uses `tcpdump` in the Docker container to sniff on the client's network traffic while requesting a location server by using the Tor network. We captured packets for every grid from 1 to 100 with 29 samples. For convenience, we did not include the captured files in this repository. They can be accessed via [this link](https://polybox.ethz.ch/index.php/s/cyhYyJPbq7oW2VO).

The collection has to be run from within the client container and can be started with the following command:

```Bash
docker exec -it cs523-client python3 /client/part3/collect_data.py
```

**Note:** One has to make sure that both client and server containers are running and that the client has valid subscription keys in its root folder `/`.

## Network traffic analysis

The captured data has to first be converted into feature sets that can be used for training the machine learning model. This is done with `python3 parse_pcap.py`, which reads all pcap files from the `data` folder collected in the last step, extract different feature sets which are stored as binary `.npy` files in the folder `parsed_features`. These feature sets can then be used to run the analysis.

The analysis can be started with `python3 fingerprinting.py`. This will start a comparison between the different feature sets extracted in the previous step. This comparison takes all possible combination of up to three feature sets, which takes several hours to conduct. This is the output we obtained by running the script, showing how the size_histogram feature set dominates the leader board:

```log
Ranking:
  1. acc:0.95833, std:0.00859, size_histogram,basic_counts
  2. acc:0.95753, std:0.00693, size_histogram,basic_counts,number_of_packets
  3. acc:0.95753, std:0.00900, size_histogram,basic_counts,percentage_incoming
  4. acc:0.95712, std:0.00859, size_histogram,percentage_incoming
  5. acc:0.95611, std:0.00824, size_histogram
  6. acc:0.95611, std:0.00757, size_histogram,occuring_outgoing_packet_sizes,percentage_incoming
  7. acc:0.95611, std:0.00799, size_histogram,basic_counts,occuring_outgoing_packet_sizes
  8. acc:0.95530, std:0.00811, size_histogram,occuring_outgoing_packet_sizes,number_of_packets
  9. acc:0.95510, std:0.00925, size_histogram,number_of_packets
 10. acc:0.95469, std:0.00747, size_histogram,occuring_outgoing_packet_sizes
 11. acc:0.95429, std:0.00825, size_histogram,percentage_incoming,number_of_packets
 12. acc:0.94681, std:0.00876, size_histogram,basic_counts,number_markers
 13. acc:0.94640, std:0.01002, size_histogram,basic_counts,size_markers
 14. acc:0.94600, std:0.00606, size_histogram,size_markers
 15. acc:0.94580, std:0.00765, size_histogram,number_markers
 16. acc:0.94559, std:0.00941, size_histogram,size_markers,percentage_incoming
 17. acc:0.94519, std:0.00742, size_histogram,number_markers,number_of_packets
 18. acc:0.94418, std:0.00700, size_histogram,size_markers,number_of_packets
 19. acc:0.94397, std:0.00682, size_histogram,number_markers,percentage_incoming
 20. acc:0.94276, std:0.00735, size_histogram,number_markers,occuring_outgoing_packet_sizes
 21. acc:0.94215, std:0.00659, size_histogram,size_markers,occuring_outgoing_packet_sizes
 22. acc:0.94094, std:0.00865, size_histogram,occuring_incoming_packet_sizes
 23. acc:0.94094, std:0.01075, size_histogram,occuring_incoming_packet_sizes,percentage_incoming
 24. acc:0.93872, std:0.01035, size_histogram,occuring_incoming_packet_sizes,number_of_packets
 25. acc:0.93669, std:0.00856, size_histogram,occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
 26. acc:0.93669, std:0.00857, size_histogram,basic_counts,occuring_incoming_packet_sizes
 27. acc:0.93548, std:0.00857, size_histogram,accum_in,basic_counts
 28. acc:0.93467, std:0.00879, size_histogram,size_markers,number_markers
 29. acc:0.93447, std:0.00931, size_histogram,accum_in
 30. acc:0.93265, std:0.01068, size_histogram,accum_in,occuring_outgoing_packet_sizes
 31. acc:0.93265, std:0.01165, size_histogram,basic_counts,packet_accums
 32. acc:0.93225, std:0.01212, size_histogram,accum_in,number_of_packets
 33. acc:0.93144, std:0.01316, size_histogram,accum_in,percentage_incoming
 34. acc:0.93022, std:0.01050, size_histogram,accum_in,number_markers
 35. acc:0.92921, std:0.01298, size_histogram,packet_accums,size_markers
 36. acc:0.92900, std:0.00827, size_histogram,packet_accums,percentage_incoming
 37. acc:0.92840, std:0.00890, size_histogram,packet_accums,number_of_packets
 38. acc:0.92820, std:0.00804, size_histogram,basic_counts,packet_lengths
 39. acc:0.92820, std:0.01035, size_histogram,packet_accums
 40. acc:0.92759, std:0.00958, size_histogram,packet_lengths
 41. acc:0.92638, std:0.01512, size_histogram,accum_in,size_markers
 42. acc:0.92638, std:0.00863, size_histogram,packet_accums,occuring_outgoing_packet_sizes
 43. acc:0.92557, std:0.01048, size_histogram,packet_lengths,occuring_outgoing_packet_sizes
 44. acc:0.92556, std:0.01052, size_histogram,accum_out,basic_counts
 45. acc:0.92516, std:0.01464, size_histogram,packet_lengths,number_of_packets
 46. acc:0.92496, std:0.01001, size_histogram,accum_out,number_of_packets
 47. acc:0.92496, std:0.00759, size_histogram,accum_out,occuring_outgoing_packet_sizes
 48. acc:0.92395, std:0.01089, size_histogram,accum_out
 49. acc:0.92375, std:0.01125, size_histogram,packet_accums,number_markers
 50. acc:0.92314, std:0.01171, size_histogram,packet_lengths,size_markers
 51. acc:0.92314, std:0.01068, size_histogram,packet_lengths,percentage_incoming
 52. acc:0.92213, std:0.01048, size_histogram,accum_out,percentage_incoming
 53. acc:0.92132, std:0.00992, size_histogram,number_markers,occuring_incoming_packet_sizes
 54. acc:0.91970, std:0.01110, size_histogram,size_markers,occuring_incoming_packet_sizes
 55. acc:0.91930, std:0.00916, size_histogram,packet_lengths,number_markers
 56. acc:0.91384, std:0.01471, size_histogram,accum_in,accum_out
 57. acc:0.91303, std:0.01241, size_histogram,accum_in,packet_lengths
 58. acc:0.91302, std:0.01222, size_histogram,accum_out,size_markers
 59. acc:0.91181, std:0.01869, size_histogram,packet_lengths,packet_accums
 60. acc:0.91120, std:0.00929, size_histogram,accum_out,number_markers
 61. acc:0.91020, std:0.01264, size_histogram,accum_out,packet_accums
 62. acc:0.90696, std:0.01221, size_histogram,accum_in,packet_accums
 63. acc:0.90069, std:0.01322, size_histogram,accum_out,packet_lengths
 64. acc:0.89806, std:0.01301, size_histogram,accum_in,occuring_incoming_packet_sizes
 65. acc:0.89179, std:0.00867, size_histogram,packet_accums,occuring_incoming_packet_sizes
 66. acc:0.88713, std:0.01392, size_histogram,packet_lengths,occuring_incoming_packet_sizes
 67. acc:0.88066, std:0.00992, size_histogram,accum_out,occuring_incoming_packet_sizes
 68. acc:0.71339, std:0.01248, accum_in,basic_counts,percentage_incoming
 69. acc:0.71157, std:0.01273, accum_in,basic_counts,occuring_outgoing_packet_sizes
 70. acc:0.70753, std:0.01730, accum_in,basic_counts
 71. acc:0.70753, std:0.01539, accum_in,basic_counts,number_of_packets
 72. acc:0.70632, std:0.01480, accum_in
 73. acc:0.70409, std:0.01753, accum_in,percentage_incoming
 74. acc:0.70288, std:0.01457, accum_in,number_of_packets
 75. acc:0.70166, std:0.01528, accum_in,occuring_outgoing_packet_sizes
 76. acc:0.70085, std:0.01566, accum_in,occuring_outgoing_packet_sizes,percentage_incoming
 77. acc:0.70065, std:0.01366, accum_in,percentage_incoming,number_of_packets
 78. acc:0.69822, std:0.01346, accum_in,occuring_outgoing_packet_sizes,number_of_packets
 79. acc:0.69741, std:0.01083, accum_in,basic_counts,size_markers
 80. acc:0.69620, std:0.01242, accum_in,basic_counts,number_markers
 81. acc:0.69479, std:0.01547, accum_in,number_markers,percentage_incoming
 82. acc:0.69276, std:0.02058, accum_in,size_markers,percentage_incoming
 83. acc:0.69236, std:0.01754, accum_in,number_markers
 84. acc:0.69074, std:0.01271, accum_in,size_markers
 85. acc:0.69054, std:0.01951, accum_in,basic_counts,packet_accums
 86. acc:0.68912, std:0.01808, accum_in,packet_accums,percentage_incoming
 87. acc:0.68912, std:0.01361, accum_in,size_markers,number_of_packets
 88. acc:0.68872, std:0.01313, accum_in,number_markers,occuring_outgoing_packet_sizes
 89. acc:0.68730, std:0.02021, accum_in,packet_accums,number_markers
 90. acc:0.68608, std:0.01381, accum_in,packet_accums,size_markers
 91. acc:0.68568, std:0.01885, accum_in,packet_accums,occuring_outgoing_packet_sizes
 92. acc:0.68548, std:0.02024, accum_in,packet_accums
 93. acc:0.68427, std:0.01962, accum_in,packet_accums,number_of_packets
 94. acc:0.68386, std:0.01427, accum_in,size_markers,occuring_outgoing_packet_sizes
 95. acc:0.68346, std:0.01149, accum_in,number_markers,number_of_packets
 96. acc:0.68144, std:0.01869, accum_in,basic_counts,occuring_incoming_packet_sizes
 97. acc:0.68022, std:0.02087, accum_in,occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
 98. acc:0.68022, std:0.01309, accum_in,occuring_incoming_packet_sizes,number_of_packets
 99. acc:0.67821, std:0.01815, accum_in,occuring_incoming_packet_sizes
100. acc:0.67658, std:0.01184, accum_in,size_markers,number_markers
101. acc:0.67597, std:0.01509, accum_in,occuring_incoming_packet_sizes,percentage_incoming
102. acc:0.67557, std:0.01771, accum_in,accum_out,packet_accums
103. acc:0.67497, std:0.01927, accum_in,packet_accums,occuring_incoming_packet_sizes
104. acc:0.67476, std:0.02046, accum_in,accum_out,basic_counts
105. acc:0.67476, std:0.01568, accum_in,basic_counts,packet_lengths
106. acc:0.67476, std:0.01360, accum_in,size_markers,occuring_incoming_packet_sizes
107. acc:0.67153, std:0.01838, basic_counts,packet_accums,percentage_incoming
108. acc:0.67152, std:0.01037, accum_in,packet_lengths,percentage_incoming
109. acc:0.67011, std:0.01477, accum_in,packet_lengths,occuring_outgoing_packet_sizes
110. acc:0.66889, std:0.01867, accum_in,accum_out,occuring_outgoing_packet_sizes
111. acc:0.66748, std:0.01821, accum_in,packet_lengths,packet_accums
112. acc:0.66708, std:0.02009, accum_in,accum_out,number_of_packets
113. acc:0.66707, std:0.02223, accum_in,accum_out,percentage_incoming
114. acc:0.66646, std:0.01543, basic_counts,packet_accums
115. acc:0.66627, std:0.01427, accum_in,number_markers,occuring_incoming_packet_sizes
116. acc:0.66545, std:0.01682, accum_in,packet_lengths,number_markers
117. acc:0.66525, std:0.01202, accum_in,packet_lengths,number_of_packets
118. acc:0.66505, std:0.00591, accum_in,packet_lengths,size_markers
119. acc:0.66343, std:0.01146, accum_in,accum_out
120. acc:0.66282, std:0.01716, accum_in,packet_lengths
121. acc:0.66122, std:0.02196, basic_counts,packet_accums,number_of_packets
122. acc:0.65959, std:0.01668, accum_in,accum_out,number_markers
123. acc:0.65899, std:0.01727, basic_counts,packet_accums,occuring_outgoing_packet_sizes
124. acc:0.65555, std:0.01745, accum_in,accum_out,size_markers
125. acc:0.65494, std:0.01367, basic_counts,packet_accums,number_markers
126. acc:0.65393, std:0.02474, accum_in,accum_out,packet_lengths
127. acc:0.65393, std:0.01430, packet_accums,size_markers
128. acc:0.65373, std:0.01630, basic_counts,packet_accums,size_markers
129. acc:0.65332, std:0.01666, packet_accums,percentage_incoming
130. acc:0.65191, std:0.02119, packet_accums,occuring_outgoing_packet_sizes,percentage_incoming
131. acc:0.65109, std:0.01272, accum_in,accum_out,occuring_incoming_packet_sizes
132. acc:0.65069, std:0.01862, packet_accums,size_markers,occuring_outgoing_packet_sizes
133. acc:0.64968, std:0.02098, packet_accums,occuring_outgoing_packet_sizes
134. acc:0.64927, std:0.01204, packet_accums,number_markers
135. acc:0.64907, std:0.01436, packet_accums,number_of_packets
136. acc:0.64887, std:0.01383, packet_accums,number_markers,occuring_outgoing_packet_sizes
137. acc:0.64846, std:0.01045, packet_accums,size_markers,number_of_packets
138. acc:0.64827, std:0.01898, packet_accums,percentage_incoming,number_of_packets
139. acc:0.64765, std:0.01336, packet_accums
140. acc:0.64725, std:0.01357, packet_accums,number_markers,percentage_incoming
141. acc:0.64644, std:0.01650, packet_accums,size_markers,percentage_incoming
142. acc:0.64604, std:0.01808, packet_accums,occuring_outgoing_packet_sizes,number_of_packets
143. acc:0.64564, std:0.01362, packet_accums,number_markers,number_of_packets
144. acc:0.64422, std:0.01420, accum_in,packet_lengths,occuring_incoming_packet_sizes
145. acc:0.64159, std:0.01648, basic_counts,packet_lengths,packet_accums
146. acc:0.64119, std:0.01835, packet_accums,size_markers,number_markers
147. acc:0.63895, std:0.01702, basic_counts,size_markers
148. acc:0.63815, std:0.01445, accum_out,basic_counts,packet_accums
149. acc:0.63673, std:0.01620, packet_accums,occuring_incoming_packet_sizes
150. acc:0.63571, std:0.02251, basic_counts,size_markers,number_of_packets
151. acc:0.63450, std:0.01768, accum_out,packet_accums
152. acc:0.63390, std:0.01321, accum_out,packet_accums,occuring_outgoing_packet_sizes
153. acc:0.63350, std:0.01329, basic_counts,packet_accums,occuring_incoming_packet_sizes
154. acc:0.63268, std:0.01151, accum_out,packet_accums,size_markers
155. acc:0.63168, std:0.01107, packet_lengths,packet_accums,percentage_incoming
156. acc:0.63067, std:0.01349, accum_out,packet_accums,number_of_packets
157. acc:0.63066, std:0.01409, packet_lengths,packet_accums,size_markers
158. acc:0.63026, std:0.01683, packet_accums,occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
159. acc:0.63006, std:0.01878, packet_accums,occuring_incoming_packet_sizes,percentage_incoming
160. acc:0.62986, std:0.01612, packet_accums,number_markers,occuring_incoming_packet_sizes
161. acc:0.62904, std:0.01680, packet_lengths,packet_accums,number_markers
162. acc:0.62903, std:0.02331, basic_counts,size_markers,percentage_incoming
163. acc:0.62825, std:0.01558, packet_accums,occuring_incoming_packet_sizes,number_of_packets
164. acc:0.62824, std:0.01415, packet_accums,size_markers,occuring_incoming_packet_sizes
165. acc:0.62803, std:0.01750, accum_out,packet_accums,percentage_incoming
166. acc:0.62622, std:0.01764, accum_out,packet_accums,number_markers
167. acc:0.62460, std:0.01460, packet_lengths,packet_accums
168. acc:0.62399, std:0.01499, packet_lengths,packet_accums,number_of_packets
169. acc:0.62258, std:0.01517, packet_lengths,packet_accums,occuring_outgoing_packet_sizes
170. acc:0.61974, std:0.01326, accum_out,packet_lengths,packet_accums
171. acc:0.61327, std:0.02042, accum_out,packet_accums,occuring_incoming_packet_sizes
172. acc:0.61226, std:0.01430, packet_lengths,packet_accums,occuring_incoming_packet_sizes
173. acc:0.61083, std:0.01361, basic_counts,size_markers,number_markers
174. acc:0.60577, std:0.02319, size_markers
175. acc:0.60315, std:0.01844, size_markers,percentage_incoming
176. acc:0.60113, std:0.01111, size_markers,number_of_packets
177. acc:0.60051, std:0.02345, basic_counts,size_markers,occuring_outgoing_packet_sizes
178. acc:0.59748, std:0.01637, size_markers,percentage_incoming,number_of_packets
179. acc:0.57361, std:0.02452, size_markers,occuring_outgoing_packet_sizes
180. acc:0.57179, std:0.02058, size_markers,number_markers,number_of_packets
181. acc:0.57037, std:0.02410, size_markers,number_markers,percentage_incoming
182. acc:0.56795, std:0.01900, size_markers,occuring_outgoing_packet_sizes,percentage_incoming
183. acc:0.56714, std:0.01905, size_markers,number_markers
184. acc:0.56248, std:0.02556, size_markers,occuring_outgoing_packet_sizes,number_of_packets
185. acc:0.55864, std:0.02191, size_markers,number_markers,occuring_outgoing_packet_sizes
186. acc:0.54469, std:0.02360, basic_counts,number_markers,percentage_incoming
187. acc:0.54105, std:0.01709, basic_counts,number_markers,number_of_packets
188. acc:0.53862, std:0.02323, basic_counts,number_markers
189. acc:0.51414, std:0.01590, basic_counts,size_markers,occuring_incoming_packet_sizes
190. acc:0.51274, std:0.02200, basic_counts,number_markers,occuring_outgoing_packet_sizes
191. acc:0.49998, std:0.02007, size_markers,number_markers,occuring_incoming_packet_sizes
192. acc:0.49090, std:0.01647, basic_counts
193. acc:0.48482, std:0.01735, number_markers
194. acc:0.48300, std:0.01894, number_markers,number_of_packets
195. acc:0.48261, std:0.02182, number_markers,percentage_incoming
196. acc:0.47451, std:0.01519, number_markers,percentage_incoming,number_of_packets
197. acc:0.46703, std:0.01749, basic_counts,number_of_packets
198. acc:0.46521, std:0.01955, basic_counts,percentage_incoming
199. acc:0.46258, std:0.01991, size_markers,occuring_incoming_packet_sizes,number_of_packets
200. acc:0.46055, std:0.01803, number_markers,occuring_outgoing_packet_sizes,number_of_packets
201. acc:0.45792, std:0.01631, number_markers,occuring_outgoing_packet_sizes
202. acc:0.45772, std:0.02102, size_markers,occuring_incoming_packet_sizes,percentage_incoming
203. acc:0.45387, std:0.02149, size_markers,occuring_incoming_packet_sizes
204. acc:0.45146, std:0.00978, number_markers,occuring_outgoing_packet_sizes,percentage_incoming
205. acc:0.44802, std:0.01878, size_markers,occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
206. acc:0.42637, std:0.00991, basic_counts,percentage_incoming,number_of_packets
207. acc:0.41788, std:0.01599, basic_counts,packet_lengths,size_markers
208. acc:0.41707, std:0.01396, accum_out,basic_counts,size_markers
209. acc:0.39543, std:0.01305, basic_counts,number_markers,occuring_incoming_packet_sizes
210. acc:0.39523, std:0.01879, accum_out,size_markers,number_markers
211. acc:0.39138, std:0.01299, packet_lengths,size_markers,number_markers
212. acc:0.38188, std:0.01021, accum_out,size_markers,percentage_incoming
213. acc:0.38127, std:0.01574, accum_out,size_markers
214. acc:0.37844, std:0.01055, accum_out,size_markers,occuring_outgoing_packet_sizes
215. acc:0.37802, std:0.01430, accum_out,basic_counts,number_markers
216. acc:0.37297, std:0.01196, accum_out,size_markers,number_of_packets
217. acc:0.37136, std:0.01621, packet_lengths,size_markers,occuring_outgoing_packet_sizes
218. acc:0.36974, std:0.01668, packet_lengths,size_markers,percentage_incoming
219. acc:0.36914, std:0.01334, packet_lengths,size_markers,number_of_packets
220. acc:0.36812, std:0.01381, packet_lengths,size_markers
221. acc:0.36145, std:0.02017, basic_counts,packet_lengths,number_markers
222. acc:0.35781, std:0.01958, accum_out,packet_lengths,size_markers
223. acc:0.35518, std:0.01888, accum_out,size_markers,occuring_incoming_packet_sizes
224. acc:0.35497, std:0.01498, accum_out,basic_counts
225. acc:0.35477, std:0.01800, accum_out,basic_counts,occuring_outgoing_packet_sizes
226. acc:0.35335, std:0.01184, accum_out,basic_counts,percentage_incoming
227. acc:0.35194, std:0.01699, accum_out,basic_counts,packet_lengths
228. acc:0.34991, std:0.02033, accum_out,basic_counts,number_of_packets
229. acc:0.34385, std:0.01710, number_markers,occuring_incoming_packet_sizes,percentage_incoming
230. acc:0.33899, std:0.01829, number_markers,occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
231. acc:0.33717, std:0.01522, basic_counts,packet_lengths,percentage_incoming
232. acc:0.33576, std:0.01935, packet_lengths,size_markers,occuring_incoming_packet_sizes
233. acc:0.33575, std:0.02017, number_markers,occuring_incoming_packet_sizes
234. acc:0.33435, std:0.00753, accum_out,number_markers,percentage_incoming
235. acc:0.33333, std:0.01485, basic_counts,packet_lengths,number_of_packets
236. acc:0.33292, std:0.01064, basic_counts,packet_lengths,occuring_outgoing_packet_sizes
237. acc:0.33292, std:0.01901, number_markers,occuring_incoming_packet_sizes,number_of_packets
238. acc:0.32867, std:0.01995, basic_counts,packet_lengths
239. acc:0.32847, std:0.01485, accum_out,number_markers,occuring_outgoing_packet_sizes
240. acc:0.32767, std:0.01443, accum_out,basic_counts,occuring_incoming_packet_sizes
241. acc:0.32665, std:0.01614, accum_out,number_markers
242. acc:0.32565, std:0.01184, accum_out,number_markers,number_of_packets
243. acc:0.32422, std:0.01970, accum_out,packet_lengths,number_markers
244. acc:0.32099, std:0.01679, accum_out,packet_lengths
245. acc:0.32038, std:0.01192, accum_out,packet_lengths,occuring_outgoing_packet_sizes
246. acc:0.31553, std:0.00867, accum_out
247. acc:0.31412, std:0.02293, accum_out,packet_lengths,percentage_incoming
248. acc:0.31372, std:0.01472, accum_out,number_markers,occuring_incoming_packet_sizes
249. acc:0.31310, std:0.01434, accum_out,percentage_incoming
250. acc:0.31229, std:0.01474, packet_lengths,number_markers,occuring_outgoing_packet_sizes
251. acc:0.31189, std:0.01268, accum_out,occuring_outgoing_packet_sizes,number_of_packets
252. acc:0.31149, std:0.00855, accum_out,occuring_outgoing_packet_sizes,percentage_incoming
253. acc:0.30905, std:0.01477, accum_out,number_of_packets
254. acc:0.30846, std:0.02005, packet_lengths,number_markers,percentage_incoming
255. acc:0.30764, std:0.01551, accum_out,packet_lengths,number_of_packets
256. acc:0.30703, std:0.01707, accum_out,occuring_outgoing_packet_sizes
257. acc:0.30562, std:0.01547, packet_lengths,number_markers,number_of_packets
258. acc:0.30542, std:0.01631, accum_out,percentage_incoming,number_of_packets
259. acc:0.30279, std:0.01185, accum_out,occuring_incoming_packet_sizes,number_of_packets
260. acc:0.30097, std:0.01450, accum_out,occuring_incoming_packet_sizes,percentage_incoming
261. acc:0.30077, std:0.01404, accum_out,occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
262. acc:0.29794, std:0.01421, accum_out,occuring_incoming_packet_sizes
263. acc:0.29773, std:0.01718, basic_counts,packet_lengths,occuring_incoming_packet_sizes
264. acc:0.29753, std:0.01296, packet_lengths,number_markers
265. acc:0.29530, std:0.00914, accum_out,packet_lengths,occuring_incoming_packet_sizes
266. acc:0.28802, std:0.02108, packet_lengths,number_markers,occuring_incoming_packet_sizes
267. acc:0.27447, std:0.01428, packet_lengths,percentage_incoming
268. acc:0.26132, std:0.01783, packet_lengths,occuring_outgoing_packet_sizes,number_of_packets
269. acc:0.26112, std:0.01530, packet_lengths,occuring_outgoing_packet_sizes,percentage_incoming
270. acc:0.26112, std:0.01215, packet_lengths,percentage_incoming,number_of_packets
271. acc:0.26092, std:0.01818, packet_lengths,occuring_outgoing_packet_sizes
272. acc:0.25707, std:0.01479, packet_lengths,number_of_packets
273. acc:0.25283, std:0.01270, packet_lengths
274. acc:0.25282, std:0.01579, packet_lengths,occuring_incoming_packet_sizes,percentage_incoming
275. acc:0.25019, std:0.01141, packet_lengths,occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
276. acc:0.24676, std:0.01296, packet_lengths,occuring_incoming_packet_sizes
277. acc:0.24352, std:0.01630, packet_lengths,occuring_incoming_packet_sizes,number_of_packets
278. acc:0.23624, std:0.01606, basic_counts,occuring_outgoing_packet_sizes,percentage_incoming
279. acc:0.23483, std:0.01531, basic_counts,occuring_outgoing_packet_sizes
280. acc:0.23220, std:0.01194, basic_counts,occuring_outgoing_packet_sizes,number_of_packets
281. acc:0.20913, std:0.01097, basic_counts,occuring_incoming_packet_sizes,number_of_packets
282. acc:0.20793, std:0.01245, basic_counts,occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
283. acc:0.20368, std:0.01568, basic_counts,occuring_incoming_packet_sizes
284. acc:0.20025, std:0.01426, basic_counts,occuring_incoming_packet_sizes,percentage_incoming
285. acc:0.13086, std:0.01137, occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes,number_of_packets
286. acc:0.11832, std:0.01047, occuring_incoming_packet_sizes,percentage_incoming,number_of_packets
287. acc:0.11610, std:0.00962, occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes
288. acc:0.11609, std:0.01145, occuring_incoming_packet_sizes,number_of_packets
289. acc:0.11004, std:0.01437, occuring_incoming_packet_sizes,occuring_outgoing_packet_sizes,percentage_incoming
290. acc:0.10316, std:0.01431, occuring_incoming_packet_sizes,percentage_incoming
291. acc:0.09931, std:0.00878, occuring_outgoing_packet_sizes,percentage_incoming,number_of_packets
292. acc:0.09709, std:0.00914, occuring_incoming_packet_sizes
293. acc:0.09283, std:0.01323, occuring_outgoing_packet_sizes,number_of_packets
294. acc:0.08414, std:0.01209, occuring_outgoing_packet_sizes,percentage_incoming
295. acc:0.07909, std:0.01150, percentage_incoming,number_of_packets
296. acc:0.07868, std:0.01582, occuring_outgoing_packet_sizes
297. acc:0.04915, std:0.00528, number_of_packets
298. acc:0.03196, std:0.00830, percentage_incoming
```

## Plots

The plots for the report were generated with the `draw_plots.py` script.
